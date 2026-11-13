use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use qos_p256::{P256Pair, P256Public};
use rand_core::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use tvc_mpp::{AppState, Record, evaluate, router};

const ISS: &str = "https://authorization.example/oauth";
const CLIENT: &str = "mpp-gateway";
const AUD: &str = "https://worker.example";
const BODY: &str = r#"{"jobId":"demo-001","record":{"ageYears":25,"country":"US"},"context":{"mppChallengeId":"challenge-001","botKeyId":"bot-thumbprint"}}"#;

struct Fixture {
    app: Router,
    key: SigningKey,
    kid: String,
    proof_key: P256Public,
    jwks: String,
}

fn fixture() -> Fixture {
    let key = SigningKey::random(&mut OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#).as_bytes(),
    ));
    let jwks = json!({"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":kid,"x":x,"y":y}]}).to_string();
    let ephemeral = P256Pair::generate().unwrap();
    let proof_key = ephemeral.public_key();
    let state = AppState::new(ephemeral, jwks.as_bytes(), ISS, AUD, CLIENT, "evaluate").unwrap();
    Fixture {
        app: router(state),
        key,
        kid,
        proof_key,
        jwks,
    }
}

fn jwt(fixture: &Fixture, replace: Option<(&str, Value)>, typ: &str) -> String {
    let now = turnkey_jwt_verify::unix_now();
    let mut claims = json!({"iss":ISS,"aud":AUD,"sub":"gateway-service","client_id":CLIENT,"scope":"evaluate","iat":now,"exp":now+60});
    if let Some((field, value)) = replace {
        claims[field] = value;
    }
    let header = json!({"alg":"ES256","typ":typ,"kid":fixture.kid});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature: Signature = fixture.key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn request(body: &str, token: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/evaluate")
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    request.body(Body::from(body.to_owned())).unwrap()
}

#[tokio::test]
async fn authenticates_computes_and_signs_the_exact_input() {
    let fixture = fixture();
    let token = jwt(&fixture, None, "at+jwt");
    let response = fixture
        .app
        .clone()
        .oneshot(request(BODY, Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(response["result"], json!({"eligible":true,"reasons":[]}));
    let proof = &response["proof"];
    let payload = proof["proofPayload"].as_str().unwrap();
    fixture
        .proof_key
        .verify(
            payload.as_bytes(),
            &qos_hex::decode(proof["signature"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        proof["publicKey"],
        qos_hex::encode(&fixture.proof_key.to_bytes())
    );
    let payload: Value = serde_json::from_str(payload).unwrap();
    assert_eq!(
        payload["inputDigest"],
        qos_hex::encode(&Sha256::digest(BODY.as_bytes()))
    );
    assert_eq!(payload["mppChallengeId"], "challenge-001");
    // OAuth tokens authorize multiple calls until expiry. MPP credential
    // replay is enforced by the separate payment gateway.
    assert_eq!(
        fixture
            .app
            .oneshot(request(&BODY.replace("demo-001", "demo-002"), Some(&token)))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn rejects_wrong_issuer_audience_client_scope_times_and_sender_binding() {
    let fixture = fixture();
    assert_eq!(
        fixture
            .app
            .clone()
            .oneshot(request(BODY, None))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let now = turnkey_jwt_verify::unix_now();
    for mutation in [
        ("iss", json!("https://other.example/oauth")),
        ("aud", json!("https://other.example")),
        ("aud", json!([AUD, "https://other.example"])),
        ("client_id", json!("other-client")),
        ("scope", json!("reevaluate")),
        ("scope", json!("evaluate\nother")),
        ("sub", json!("")),
        ("exp", json!(now - 10)),
        ("exp", json!(now + 301)),
        ("iat", json!(now + 60)),
        ("nbf", json!(now + 60)),
        ("cnf", json!({"jkt":"sender-bound"})),
        ("cnf", Value::Null),
    ] {
        let token = jwt(&fixture, Some(mutation), "at+jwt");
        assert_eq!(
            fixture
                .app
                .clone()
                .oneshot(request(BODY, Some(&token)))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let token = jwt(&fixture, None, "JWT");
    assert_eq!(
        fixture
            .app
            .oneshot(request(BODY, Some(&token)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn accepts_a_required_scope_among_other_scopes() {
    let fixture = fixture();
    let token = jwt(
        &fixture,
        Some(("scope", json!("other evaluate extra"))),
        "at+jwt",
    );
    assert_eq!(
        fixture
            .app
            .oneshot(request(BODY, Some(&token)))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn rejects_unknown_fields_bad_values_and_oversized_body() {
    let fixture = fixture();
    let token = jwt(&fixture, None, "at+jwt");
    for body in [
        BODY.replace("25", "131"),
        BODY.replace("\"US\"", "\"us\""),
        BODY.replacen("{", "{\"unknown\":true,", 1),
        BODY.replace("demo-001", "../job"),
    ] {
        assert_eq!(
            fixture
                .app
                .clone()
                .oneshot(request(&body, Some(&token)))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        fixture
            .app
            .oneshot(request(&"x".repeat(16_385), Some(&token)))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[test]
fn rule_order_is_stable() {
    assert_eq!(
        evaluate(&Record {
            age_years: 17,
            country: "CA".into()
        })
        .reasons,
        vec!["under_age", "unsupported_country"]
    );
}

#[tokio::test]
async fn accepts_es256_tokens_from_a_mixed_algorithm_jwks() {
    let fixture = fixture();
    let mut jwks: Value = serde_json::from_str(&fixture.jwks).unwrap();
    jwks["keys"].as_array_mut().unwrap().push(json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"other-algorithm","x":URL_SAFE_NO_PAD.encode([1u8;32])}));
    let state = AppState::new(
        P256Pair::generate().unwrap(),
        jwks.to_string().as_bytes(),
        ISS,
        AUD,
        CLIENT,
        "evaluate",
    )
    .unwrap();
    let token = jwt(&fixture, None, "at+jwt");
    assert_eq!(
        router(state)
            .oneshot(request(BODY, Some(&token)))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
