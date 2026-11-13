//! OAuth resource-server validation. This app does not issue access tokens.

use serde::Deserialize;
use turnkey_jwt_verify::{JwsRules, PinnedKeySet, TimeRules, check_times, verify};

pub struct AccessPolicy {
    issuer: String,
    audience: String,
    client_id: String,
    scope: String,
    keys: PinnedKeySet,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    client_id: String,
    scope: String,
    iat: u64,
    exp: u64,
    nbf: Option<u64>,
}

impl AccessPolicy {
    pub fn new(
        jwks: &[u8],
        issuer: &str,
        audience: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let issuer_url = url::Url::parse(issuer)?;
        let audience_url = url::Url::parse(audience)?;
        if issuer_url.scheme() != "https"
            || issuer_url.host_str().is_none()
            || !issuer_url.username().is_empty()
            || issuer_url.password().is_some()
            || issuer_url.query().is_some()
            || issuer_url.fragment().is_some()
        {
            return Err("issuer must be a fixed HTTPS URL".into());
        }
        if audience_url.scheme() != "https"
            || audience_url.origin().ascii_serialization() != audience
            || !audience_url.username().is_empty()
            || audience_url.password().is_some()
        {
            return Err("audience must be a canonical HTTPS origin".into());
        }
        if client_id.is_empty()
            || client_id.len() > 256
            || scope.is_empty()
            || scope.len() > 128
            || scope
                .bytes()
                .any(|b| !(0x21..=0x7e).contains(&b) || b == b'"' || b == b'\\')
        {
            return Err("configure a client identity and one valid OAuth scope token".into());
        }
        let raw_keys: serde_json::Value = serde_json::from_slice(jwks)?;
        let all_keys = raw_keys
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .filter(|keys| !keys.is_empty() && keys.len() <= 8)
            .ok_or("JWKS must contain 1–8 public signing keys")?;
        let mut es256_keys = vec![];
        for key in all_keys {
            if !key.is_object() || key.get("d").is_some() {
                return Err("JWKS must contain public keys only".into());
            }
            if key.get("kty").and_then(serde_json::Value::as_str) == Some("EC")
                && key.get("crv").and_then(serde_json::Value::as_str) == Some("P-256")
                && key
                    .get("alg")
                    .is_none_or(|alg| alg.as_str() == Some("ES256"))
            {
                es256_keys.push(key.clone());
            }
        }
        // Identity's shared JWKS can also carry Ed25519 attestation keys.
        // Only the ES256 subset is eligible for these OAuth access tokens.
        let selected_jwks = serde_json::to_vec(&serde_json::json!({"keys":es256_keys}))?;
        Ok(Self {
            issuer: issuer.into(),
            audience: audience.into(),
            client_id: client_id.into(),
            scope: scope.into(),
            keys: PinnedKeySet::from_jwks_json(&selected_jwks)?,
        })
    }

    pub fn authorize(&self, token: &str, now: u64) -> Result<(), ()> {
        // The library fixes ES256, requires typ at+jwt, bounds token size,
        // rejects duplicate JSON members, and selects a configured trusted key.
        let verified =
            verify(token, &JwsRules::new("at+jwt", 12 * 1024), &self.keys).map_err(|_| ())?;
        let raw: serde_json::Value = verified.claims().map_err(|_| ())?;
        // This resource implements bearer access, not DPoP or certificate-bound
        // access tokens. Silently ignoring cnf would bypass sender constraints.
        if raw.get("cnf").is_some() {
            return Err(());
        }
        let claims: Claims = serde_json::from_value(raw).map_err(|_| ())?;
        let audience_matches = match claims.aud {
            Audience::One(aud) => aud == self.audience,
            Audience::Many(aud) => aud.len() == 1 && aud[0] == self.audience,
        };
        if claims.iss != self.issuer
            || !audience_matches
            || claims.client_id != self.client_id
            || claims.sub.is_empty()
            || claims.sub.len() > 512
            || claims.scope.len() > 4096
            || claims
                .scope
                .bytes()
                .any(|b| !(0x20..=0x7e).contains(&b) || b == b'"' || b == b'\\')
            || !claims
                .scope
                .split_ascii_whitespace()
                .any(|scope| scope == self.scope)
        {
            return Err(());
        }
        if claims.nbf.is_some_and(|nbf| nbf > now.saturating_add(5)) {
            return Err(());
        }
        check_times(claims.iat, claims.exp, now, &TimeRules::new(5, 300)).map_err(|_| ())?;
        Ok(())
    }
}
