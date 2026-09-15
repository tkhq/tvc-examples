//! Select applicable activities and evaluate their signing intent without I/O.

use crate::aptos_policy::{
    Address, AptosRejectReason, evaluate_aptos_transfer_policy,
    parse_and_validate_aptos_transaction,
};
use serde::Deserialize;
use std::fmt;

const CONSENSUS_NEEDED: &str = "ACTIVITY_STATUS_CONSENSUS_NEEDED";
const SIGN_RAW_PAYLOAD_V2: &str = "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2";

/// Typed result of evaluating an authenticated activity update.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) enum ActivityDecision {
    Approve(ApproveReason),
    Reject(RejectReason),
    Ignore(IgnoreReason),
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) enum ApproveReason {
    NativeAptosTransfer { total_octas: u64 },
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) enum RejectReason {
    InvalidPayload,
    InvalidHexPayload,
    UnsupportedPayloadEncoding,
    UnsupportedHashFunction,
    InvalidAptosTransaction(AptosRejectReason),
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) enum IgnoreReason {
    NotConsensusNeeded,
    NotSignRawPayloadV2,
    UnsupportedSignerFormat,
}

impl fmt::Display for ApproveReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeAptosTransfer { total_octas } => {
                write!(
                    formatter,
                    "native-APT transfer within policy ({total_octas} octas including maximum gas cost)"
                )
            }
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayload => {
                formatter.write_str("Aptos raw-signing request needs a nonempty string payload")
            }
            Self::InvalidHexPayload => {
                formatter.write_str("payload must be unprefixed hexadecimal bytes")
            }
            Self::UnsupportedPayloadEncoding => {
                formatter.write_str("payload encoding must be PAYLOAD_ENCODING_HEXADECIMAL")
            }
            Self::UnsupportedHashFunction => {
                formatter.write_str("hash function must be HASH_FUNCTION_NOT_APPLICABLE")
            }
            Self::InvalidAptosTransaction(reason) => reason.fmt(formatter),
        }
    }
}

impl fmt::Display for IgnoreReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConsensusNeeded => formatter.write_str("activity does not need consensus"),
            Self::NotSignRawPayloadV2 => formatter.write_str("activity is not sign-raw-payload v2"),
            Self::UnsupportedSignerFormat => formatter
                .write_str("signWith must be 0x followed by 64 lowercase hexadecimal digits"),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ActivityWebhookPayload {
    pub(super) id: String,
    pub(super) organization_id: String,
    status: String,
    #[serde(rename = "type")]
    activity_type: String,
    #[serde(default)]
    pub(super) fingerprint: Option<String>,
    #[serde(default)]
    intent: Option<ActivityIntentDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivityIntentDto {
    #[serde(default)]
    sign_raw_payload_intent_v2: Option<SignRawPayloadIntentDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignRawPayloadIntentDto {
    sign_with: String,
    // Preserve invalid field types so an authenticated, applicable request gets a reject vote.
    #[serde(default)]
    payload: serde_json::Value,
    #[serde(default)]
    encoding: serde_json::Value,
    #[serde(default)]
    hash_function: serde_json::Value,
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) enum ActivityPayloadError {
    MissingSignRawPayloadIntent,
    MissingFingerprint,
}

impl fmt::Display for ActivityPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSignRawPayloadIntent => {
                formatter.write_str("sign-raw-payload activity has no v2 intent")
            }
            Self::MissingFingerprint => {
                formatter.write_str("actionable activity has no fingerprint")
            }
        }
    }
}

pub(super) fn evaluate_activity(
    activity: &ActivityWebhookPayload,
) -> Result<ActivityDecision, ActivityPayloadError> {
    if activity.status != CONSENSUS_NEEDED {
        return Ok(ActivityDecision::Ignore(IgnoreReason::NotConsensusNeeded));
    }
    // Extend activity dispatch here when adding another supported intent. Each branch
    // must validate its own signing format before approving; unknown types cast no vote.
    if activity.activity_type != SIGN_RAW_PAYLOAD_V2 {
        return Ok(ActivityDecision::Ignore(IgnoreReason::NotSignRawPayloadV2));
    }
    let sign_raw_payload = activity
        .intent
        .as_ref()
        .and_then(|intent| intent.sign_raw_payload_intent_v2.as_ref())
        .ok_or(ActivityPayloadError::MissingSignRawPayloadIntent)?;
    let Some(aptos_sender) = Address::canonical(&sign_raw_payload.sign_with) else {
        return Ok(ActivityDecision::Ignore(
            IgnoreReason::UnsupportedSignerFormat,
        ));
    };
    Ok(
        match evaluate_aptos_raw_payload(sign_raw_payload, aptos_sender) {
            Ok(reason) => ActivityDecision::Approve(reason),
            Err(reason) => ActivityDecision::Reject(reason),
        },
    )
}

fn evaluate_aptos_raw_payload(
    intent: &SignRawPayloadIntentDto,
    sender: Address,
) -> Result<ApproveReason, RejectReason> {
    let payload = intent
        .payload
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or(RejectReason::InvalidPayload)?;
    if intent.encoding.as_str() != Some("PAYLOAD_ENCODING_HEXADECIMAL") {
        return Err(RejectReason::UnsupportedPayloadEncoding);
    }
    if intent.hash_function.as_str() != Some("HASH_FUNCTION_NOT_APPLICABLE") {
        return Err(RejectReason::UnsupportedHashFunction);
    }
    // Do not accept prefixes, whitespace, or partial bytes in signing payloads.
    if !payload.len().is_multiple_of(2) || !payload.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RejectReason::InvalidHexPayload);
    }
    let transaction_bytes =
        qos_hex::decode(payload).map_err(|_| RejectReason::InvalidHexPayload)?;
    let validated = parse_and_validate_aptos_transaction(&transaction_bytes, sender)
        .map_err(RejectReason::InvalidAptosTransaction)?;
    evaluate_aptos_transfer_policy(&validated.transaction, &validated.summary)
        .map_err(RejectReason::InvalidAptosTransaction)?;
    Ok(ApproveReason::NativeAptosTransfer {
        total_octas: validated.summary.total_octas,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::super::test_support::activity_fixture;
    use super::*;
    use crate::aptos_policy::tests::{other_sender, over_limit_message, sender};

    #[test]
    fn classifies_only_canonical_signer_addresses() {
        let canonical = sender().to_string();
        assert_eq!(Address::canonical(&canonical), Some(sender()));
        assert_eq!(Address::canonical("0x0"), None);
        assert_eq!(Address::canonical(&canonical.to_uppercase()), None);
        assert_eq!(Address::canonical("not-an-address"), None);
        assert_eq!(Address::canonical(&format!("0x{}", "AB".repeat(32))), None);
        assert_eq!(
            Address::canonical("00000000-0000-0000-0000-000000000000"),
            None
        );
    }

    fn evaluate_fixture(
        value: serde_json::Value,
    ) -> Result<ActivityDecision, ActivityPayloadError> {
        let activity = serde_json::from_value(value).expect("activity DTO should deserialize");
        evaluate_activity(&activity)
    }

    #[test]
    fn validates_raw_payload_parameters_before_parsing_transactions() {
        use serde_json::json;
        for (field, invalid_values, reason) in [
            (
                "payload",
                vec![json!(null), json!(""), json!(123), json!({})],
                RejectReason::InvalidPayload,
            ),
            (
                "encoding",
                vec![
                    json!(null),
                    json!(false),
                    json!("PAYLOAD_ENCODING_TEXT_UTF8"),
                    json!("future-encoding"),
                ],
                RejectReason::UnsupportedPayloadEncoding,
            ),
            (
                "hashFunction",
                vec![
                    json!(null),
                    json!([]),
                    json!("HASH_FUNCTION_NO_OP"),
                    json!("HASH_FUNCTION_SHA256"),
                    json!("HASH_FUNCTION_KECCAK256"),
                ],
                RejectReason::UnsupportedHashFunction,
            ),
        ] {
            let expected = Ok(ActivityDecision::Reject(reason));
            for invalid_value in invalid_values {
                let mut activity = activity_fixture();
                activity["intent"]["signRawPayloadIntentV2"][field] = invalid_value;
                assert_eq!(evaluate_fixture(activity), expected, "field {field}");
            }
        }
        for field in ["payload", "encoding", "hashFunction"] {
            let mut activity = activity_fixture();
            activity["intent"]["signRawPayloadIntentV2"]
                .as_object_mut()
                .expect("intent is an object")
                .remove(field);
            let reason = match field {
                "payload" => RejectReason::InvalidPayload,
                "encoding" => RejectReason::UnsupportedPayloadEncoding,
                _ => RejectReason::UnsupportedHashFunction,
            };
            assert_eq!(
                evaluate_fixture(activity),
                Ok(ActivityDecision::Reject(reason))
            );
        }
        for payload in ["invalid", "0", "0x00", "00\n", "é"] {
            let mut activity = activity_fixture();
            activity["intent"]["signRawPayloadIntentV2"]["payload"] = json!(payload);
            assert_eq!(
                evaluate_fixture(activity),
                Ok(ActivityDecision::Reject(RejectReason::InvalidHexPayload))
            );
        }
        for payload in ["00".to_owned(), "ab".repeat(32)] {
            let mut activity = activity_fixture();
            activity["intent"]["signRawPayloadIntentV2"]["payload"] = json!(payload);
            assert_eq!(
                evaluate_fixture(activity),
                Ok(ActivityDecision::Reject(
                    RejectReason::InvalidAptosTransaction(AptosRejectReason::InvalidSigningPrefix)
                ))
            );
        }
    }

    #[test]
    fn applies_aptos_policy_to_decoded_raw_bytes() {
        assert_eq!(
            evaluate_fixture(activity_fixture()),
            Ok(ActivityDecision::Approve(
                ApproveReason::NativeAptosTransfer {
                    total_octas: 100_200_000
                }
            ))
        );
        let mut mismatch = activity_fixture();
        mismatch["intent"]["signRawPayloadIntentV2"]["signWith"] =
            serde_json::json!(other_sender().to_string());
        assert_eq!(
            evaluate_fixture(mismatch),
            Ok(ActivityDecision::Reject(
                RejectReason::InvalidAptosTransaction(AptosRejectReason::SenderMismatch)
            ))
        );

        let mut excessive = activity_fixture();
        excessive["intent"]["signRawPayloadIntentV2"]["payload"] =
            serde_json::json!(qos_hex::encode(&over_limit_message()));
        assert_eq!(
            evaluate_fixture(excessive),
            Ok(ActivityDecision::Reject(
                RejectReason::InvalidAptosTransaction(AptosRejectReason::TotalExceedsLimit {
                    total_octas: crate::aptos_policy::MAX_TOTAL_OCTAS + 100_000_000
                })
            ))
        );
    }

    #[test]
    fn ignores_unsupported_signer_format_and_non_signing_activities() {
        let unsupported_signer_format: ActivityWebhookPayload =
            serde_json::from_value(serde_json::json!({
                "id": "activity-id",
                "organizationId": "organization-id",
                "status": CONSENSUS_NEEDED,
                "type": SIGN_RAW_PAYLOAD_V2,
                "intent": { "signRawPayloadIntentV2": { "signWith": "0x1234" } }
            }))
            .expect("payload should deserialize");
        assert_eq!(
            evaluate_activity(&unsupported_signer_format),
            Ok(ActivityDecision::Ignore(
                IgnoreReason::UnsupportedSignerFormat
            ))
        );

        let export_wallet: ActivityWebhookPayload = serde_json::from_value(serde_json::json!({
            "id": "activity-id",
            "organizationId": "organization-id",
            "status": CONSENSUS_NEEDED,
            "type": "ACTIVITY_TYPE_EXPORT_WALLET",
            "intent": {}
        }))
        .expect("payload should deserialize");
        assert_eq!(
            evaluate_activity(&export_wallet),
            Ok(ActivityDecision::Ignore(IgnoreReason::NotSignRawPayloadV2))
        );
    }

    #[test]
    fn rejects_missing_data_after_address_eligibility_and_ignores_other_statuses() {
        let missing_transaction: ActivityWebhookPayload =
            serde_json::from_value(serde_json::json!({
                "id": "activity-id",
                "organizationId": "organization-id",
                "status": CONSENSUS_NEEDED,
                "type": SIGN_RAW_PAYLOAD_V2,
                "intent": {
                    "signRawPayloadIntentV2": {
                        "signWith": sender().to_string()
                    }
                }
            }))
            .expect("payload should deserialize");
        assert_eq!(
            evaluate_activity(&missing_transaction),
            Ok(ActivityDecision::Reject(RejectReason::InvalidPayload))
        );

        let completed: ActivityWebhookPayload = serde_json::from_value(serde_json::json!({
            "id": "activity-id",
            "organizationId": "organization-id",
            "status": "ACTIVITY_STATUS_COMPLETED",
            "type": SIGN_RAW_PAYLOAD_V2
        }))
        .expect("payload should deserialize");
        assert_eq!(
            evaluate_activity(&completed),
            Ok(ActivityDecision::Ignore(IgnoreReason::NotConsensusNeeded))
        );
    }

    #[test]
    fn ignores_legacy_and_batch_requests_and_requires_raw_intent() {
        for activity_type in [
            "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
            "ACTIVITY_TYPE_SIGN_TRANSACTION",
            "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD",
            "ACTIVITY_TYPE_SIGN_RAW_PAYLOADS",
        ] {
            let mut activity = activity_fixture();
            activity["type"] = serde_json::json!(activity_type);
            assert_eq!(
                evaluate_fixture(activity),
                Ok(ActivityDecision::Ignore(IgnoreReason::NotSignRawPayloadV2))
            );
        }
        let mut activity = activity_fixture();
        activity["intent"] = serde_json::json!({});
        assert_eq!(
            evaluate_fixture(activity),
            Err(ActivityPayloadError::MissingSignRawPayloadIntent)
        );
    }
}
