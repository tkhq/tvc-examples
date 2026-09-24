#![allow(missing_docs, clippy::unwrap_used)]

use e2e::TestArgs;
use qos_p256::P256Public;

#[tokio::test]
async fn test_health() {
    async fn test(test_args: TestArgs) {
        let response = reqwest::get(format!("{}/health", test_args.base_url))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let json: serde_json::Value = response.json().await.unwrap();
        assert_eq!(json["status"], "healthy");
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_dashboard() {
    async fn test(test_args: TestArgs) {
        let response = reqwest::get(&test_args.base_url).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        assert!(body.contains("A signed price, carried on-chain."));
        assert!(body.contains("/oracle/status"));
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_app_proof() {
    async fn test(test_args: TestArgs) {
        let response = reqwest::get(format!("{}/app-proof", test_args.base_url))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let json: serde_json::Value = response.json().await.unwrap();
        let payload = json["proof"]["payload"].as_str().unwrap();
        let public_key = P256Public::from_bytes(
            &qos_hex::decode(json["proof"]["public_key"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let signature = qos_hex::decode(json["proof"]["signature"].as_str().unwrap()).unwrap();
        public_key.verify(payload.as_bytes(), &signature).unwrap();
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_metrics() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        client
            .get(format!("{}/health", test_args.base_url))
            .send()
            .await
            .unwrap();
        let response = client
            .get(format!("{}/metrics", test_args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("tvc_http_request_duration_ms")
        );
    }
    e2e::Builder::new().execute(test).await;
}
