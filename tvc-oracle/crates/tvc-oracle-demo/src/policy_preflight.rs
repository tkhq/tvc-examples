//! One-time, non-broadcast checks for the oracle updater's Turnkey policy.

use crate::state::AppState;
use std::io;
use turnkey_client::{
    TurnkeyClientError,
    generated::immutable::{activity::v1::SignTransactionIntentV2, common::v1::TransactionType},
};

const ORGANIZATION_ID: &str = "e4c1c7b7-bcad-4467-ac4c-f34447f4cdcd";
const UPDATER_ADDRESS: &str = "0x13A586dDB307E183aB167D4fB4a67536F8891D2f";

struct Case {
    name: &'static str,
    unsigned_transaction: String,
    should_sign: bool,
}

/// Exercise the live Turnkey policy using the enclave-provisioned quorum credential.
///
/// A successful signature is deliberately discarded, and no transaction is broadcast.
pub async fn run(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("starting non-broadcast Turnkey policy preflight");

    for case in cases()? {
        let result = state
            .turnkey_client
            .sign_transaction(
                ORGANIZATION_ID.to_owned(),
                state.turnkey_client.current_timestamp(),
                SignTransactionIntentV2 {
                    sign_with: UPDATER_ADDRESS.to_owned(),
                    unsigned_transaction: case.unsigned_transaction,
                    r#type: TransactionType::Ethereum,
                },
            )
            .await;

        match (case.should_sign, result) {
            (true, Ok(activity)) => tracing::info!(
                case = case.name,
                activity_id = activity.activity_id,
                "policy allowed expected transaction; signature discarded"
            ),
            (false, Err(error)) if is_policy_denial(&error) => {
                tracing::info!(case = case.name, "policy denied transaction as expected");
            }
            (true, Err(error)) => {
                return Err(io::Error::other(format!(
                    "policy preflight '{}' should have been allowed: {error}",
                    case.name
                ))
                .into());
            }
            (false, Ok(activity)) => {
                return Err(io::Error::other(format!(
                    "policy preflight '{}' was unexpectedly signed (activity {}); signature discarded",
                    case.name, activity.activity_id
                ))
                .into());
            }
            (false, Err(error)) => {
                return Err(io::Error::other(format!(
                    "policy preflight '{}' failed for a reason other than policy denial: {error}",
                    case.name
                ))
                .into());
            }
        }
    }

    tracing::info!("Turnkey policy preflight passed; no transaction was broadcast");
    Ok(())
}

fn is_policy_denial(error: &TurnkeyClientError) -> bool {
    match error {
        TurnkeyClientError::ActivityFailed(_) | TurnkeyClientError::ActivityRequiresApproval(_) => {
            true
        }
        // Rejected signing activities do not contain a signing result. The generated
        // SDK attempts to decode that result before returning the activity status, so
        // policy denials currently surface as one of these missing-result errors.
        TurnkeyClientError::MissingResult | TurnkeyClientError::MissingInnerResult => true,
        TurnkeyClientError::UnexpectedActivityStatus(status) => {
            status == "ACTIVITY_STATUS_REJECTED"
        }
        TurnkeyClientError::UnexpectedHttpStatus(403, body) => {
            is_policy_engine_permission_error(body)
        }
        _ => false,
    }
}

fn is_policy_engine_permission_error(body: &str) -> bool {
    let Ok(body) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };

    body.get("details")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|details| {
            details.iter().any(|detail| {
                detail.get("@type").and_then(serde_json::Value::as_str)
                    == Some("type.googleapis.com/errors.v1.PolicyEnginePermissionError")
            })
        })
}

fn cases() -> Result<Vec<Case>, io::Error> {
    Ok(vec![
        Case::allowed("exact permitted update", VALID),
        Case::denied(
            "wrong destination",
            replace_once(
                VALID,
                "9890df3894ebf1dbcd8e69aa7faffba089d8bf6b",
                "1111111111111111111111111111111111111111",
            )?,
        ),
        Case::denied("wrong function", WRONG_FUNCTION.to_owned()),
        Case::denied(
            "wrong template",
            replace_once(
                VALID,
                "deda2f7938bf877d2f011aa550852d3459794e16944ea0b7513465479752ba93",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )?,
        ),
        Case::denied(
            "nonzero value",
            replace_once(
                VALID,
                "9890df3894ebf1dbcd8e69aa7faffba089d8bf6b80b90144",
                "9890df3894ebf1dbcd8e69aa7faffba089d8bf6b01b90144",
            )?,
        ),
        Case::denied(
            "gas above cap",
            replace_once(VALID, "83030d40", "8303d091")?,
        ),
        Case::denied(
            "max fee above cap",
            replace_once(VALID, "85012a05f200", "8502540be401")?,
        ),
        Case::denied("wrong chain", WRONG_CHAIN.to_owned()),
    ])
}

impl Case {
    fn allowed(name: &'static str, transaction: &str) -> Self {
        Self {
            name,
            unsigned_transaction: transaction.to_owned(),
            should_sign: true,
        }
    }

    fn denied(name: &'static str, unsigned_transaction: String) -> Self {
        Self {
            name,
            unsigned_transaction,
            should_sign: false,
        }
    }
}

fn replace_once(value: &str, from: &str, to: &str) -> Result<String, io::Error> {
    if value.matches(from).count() != 1 {
        return Err(io::Error::other(format!(
            "preflight fixture expected exactly one occurrence of {from}"
        )));
    }
    Ok(value.replacen(from, to, 1))
}

// EIP-1559, Sepolia, nonce 0, 200k gas, 1 gwei priority / 5 gwei max fee,
// zero value, exact oracle address, updatePrice selector, and exact template.
pub(crate) const VALID: &str = "02f9017283aa36a780843b9aca0085012a05f20083030d40949890df3894ebf1dbcd8e69aa7faffba089d8bf6b80b9014490155da8deda2f7938bf877d2f011aa550852d3459794e16944ea0b7513465479752ba93000000000000000000000000000000000000000000000000000000006a988a81000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000081a0fb87b87153000000000000000000000000000000000000000000000000000000000000000000416a157125cc065e38c66d6b978f8897d7693282462f041fb68bbdd49cbc5b8322143c59e8ac68aacdb2533a5247e0fb50601a0bbd7f8c1e4a7e5627d685dbb3361c00000000000000000000000000000000000000000000000000000000000000c0";
const WRONG_FUNCTION: &str = "02f85083aa36a780843b9aca0085012a05f20083030d40949890df3894ebf1dbcd8e69aa7faffba089d8bf6b80a49d54f4190000000000000000000000001111111111111111111111111111111111111111c0";
const WRONG_CHAIN: &str = "02f9016f0180843b9aca0085012a05f20083030d40949890df3894ebf1dbcd8e69aa7faffba089d8bf6b80b9014490155da8deda2f7938bf877d2f011aa550852d3459794e16944ea0b7513465479752ba93000000000000000000000000000000000000000000000000000000006a988a81000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000081a0fb87b87153000000000000000000000000000000000000000000000000000000000000000000416a157125cc065e38c66d6b978f8897d7693282462f041fb68bbdd49cbc5b8322143c59e8ac68aacdb2533a5247e0fb50601a0bbd7f8c1e4a7e5627d685dbb3361c00000000000000000000000000000000000000000000000000000000000000c0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_has_one_allow_and_seven_denials() -> Result<(), io::Error> {
        let cases = cases()?;
        assert_eq!(cases.iter().filter(|case| case.should_sign).count(), 1);
        assert_eq!(cases.iter().filter(|case| !case.should_sign).count(), 7);
        assert!(
            cases
                .iter()
                .all(|case| case.unsigned_transaction.starts_with("02"))
        );
        Ok(())
    }

    #[test]
    fn rejected_activity_result_shapes_are_policy_denials() {
        assert!(is_policy_denial(&TurnkeyClientError::MissingResult));
        assert!(is_policy_denial(&TurnkeyClientError::MissingInnerResult));
    }

    #[test]
    fn structured_policy_engine_403_is_a_policy_denial() {
        let body = serde_json::json!({
            "code": 7,
            "message": "You don't have sufficient permissions to take this action.",
            "details": [{
                "@type": "type.googleapis.com/errors.v1.PolicyEnginePermissionError",
                "message": "No policies evaluated to outcome: Allow"
            }]
        })
        .to_string();

        assert!(is_policy_denial(&TurnkeyClientError::UnexpectedHttpStatus(
            403, body
        )));
    }

    #[test]
    fn unrelated_http_errors_are_not_policy_denials() {
        let unrelated_403 = TurnkeyClientError::UnexpectedHttpStatus(
            403,
            serde_json::json!({"code": 7, "details": []}).to_string(),
        );
        let quota_error = TurnkeyClientError::UnexpectedHttpStatus(
            429,
            serde_json::json!({
                "details": [{
                    "@type": "type.googleapis.com/errors.v1.PolicyEnginePermissionError"
                }]
            })
            .to_string(),
        );

        assert!(!is_policy_denial(&unrelated_403));
        assert!(!is_policy_denial(&quota_error));
    }
}
