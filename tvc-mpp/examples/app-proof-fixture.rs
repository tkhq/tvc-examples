//! Emit a public synthetic proof for the cross-language signature test.
//! This creates an un-attested key in memory and never outputs its private half.
use qos_p256::P256Pair;
use tvc_mpp::{ExecutionRequest, create_app_proof, evaluate};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let body = br#"{"jobId":"rust-fixture","record":{"ageYears":25,"country":"US"},"context":{"mppChallengeId":"synthetic-challenge","botKeyId":"synthetic-bot"}}"#;
    let request: ExecutionRequest = serde_json::from_slice(body)?;
    let key = P256Pair::generate().map_err(|_| "key generation failed")?;
    let proof = create_app_proof(
        &key,
        &request,
        body,
        &evaluate(&request.record),
        "1700000000000".into(),
    )?;
    println!("{}", serde_json::to_string_pretty(&proof)?);
    Ok(())
}
