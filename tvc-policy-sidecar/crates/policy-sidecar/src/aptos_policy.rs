//! Narrow, offline validation of standard Aptos Ed25519 transfer signing messages.

use serde::{
    Deserialize,
    de::{self, EnumAccess, VariantAccess, Visitor},
};
use sha3::{Digest as _, Sha3_256};
use std::fmt;

pub(crate) const MAX_TOTAL_OCTAS: u64 = 1_000_000_000;
const ALLOWED_RECIPIENT: Address = Address([7; 32]);

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug, serde::Serialize))]
pub(crate) struct Address([u8; 32]);

impl Address {
    pub(crate) fn canonical(value: &str) -> Option<Self> {
        if value.len() != 66
            || !value.starts_with("0x")
            || !value[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        Some(Self(qos_hex::decode(&value[2..]).ok()?.try_into().ok()?))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", qos_hex::encode(&self.0))
    }
}

// RawTransaction's exact BCS field order. These wire types intentionally remain private.
#[derive(Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, serde::Serialize))]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Preserve sequence, expiration and chain ID in the wire model without adding demo policies"
    )
)]
pub(crate) struct RawTransaction {
    sender: Address,
    sequence_number: u64,
    payload: EntryFunctionPayload,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp_secs: u64,
    chain_id: u8,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, serde::Serialize))]
struct ModuleId {
    address: Address,
    name: String,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, serde::Serialize))]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The type argument vector is validated as empty during deserialization"
    )
)]
struct EntryFunction {
    module: ModuleId,
    function: String,
    // No TypeTag variant is supported: an empty vector decodes, any tag fails closed.
    type_args: Vec<UnsupportedTypeTag>,
    args: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, serde::Serialize))]
enum UnsupportedTypeTag {}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct EntryFunctionPayload(EntryFunction);

impl<'de> Deserialize<'de> for EntryFunctionPayload {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PayloadVisitor;
        impl<'de> Visitor<'de> for PayloadVisitor {
            type Value = EntryFunctionPayload;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("Aptos EntryFunction payload (variant 2)")
            }
            fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
                let (index, variant) = data.variant::<u32>()?;
                // Real Aptos indices: Script=0, ModuleBundle=1, EntryFunction=2,
                // Multisig=3. Reject all other indices without interpreting their bodies.
                if index != 2 {
                    return Err(de::Error::custom("unsupported Aptos transaction payload"));
                }
                Ok(EntryFunctionPayload(variant.newtype_variant()?))
            }
        }
        deserializer.deserialize_enum(
            "TransactionPayload",
            &["Script", "ModuleBundle", "EntryFunction", "Multisig"],
            PayloadVisitor,
        )
    }
}

#[cfg(test)]
impl serde::Serialize for EntryFunctionPayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_variant("TransactionPayload", 2, "EntryFunction", &self.0)
    }
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Retain principal and gas separately for the policy extension point"
    )
)]
pub(crate) struct TransferSummary {
    recipient: Address,
    transferred_octas: u64,
    maximum_gas_cost_octas: u64,
    pub(crate) total_octas: u64,
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) struct ValidatedAptosTransaction {
    pub(crate) transaction: RawTransaction,
    pub(crate) summary: TransferSummary,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AptosRejectReason {
    InvalidSigningPrefix,
    InvalidTransactionBcs,
    SenderMismatch,
    UnsupportedFunction,
    InvalidArguments,
    ArithmeticOverflow,
    RecipientNotAllowed,
    TotalExceedsLimit { total_octas: u64 },
}

impl fmt::Display for AptosRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSigningPrefix => {
                f.write_str("payload must start with SHA3-256(APTOS::RawTransaction)")
            }
            Self::InvalidTransactionBcs => {
                f.write_str("malformed or unsupported Aptos RawTransaction BCS")
            }
            Self::SenderMismatch => f.write_str("Aptos transaction sender does not match signWith"),
            Self::UnsupportedFunction => {
                f.write_str("only 0x1::aptos_account::transfer is supported")
            }
            Self::InvalidArguments => {
                f.write_str("transfer requires exactly a BCS address and a BCS u64 amount")
            }
            Self::ArithmeticOverflow => {
                f.write_str("Aptos transfer plus maximum gas cost overflows u64")
            }
            Self::RecipientNotAllowed => f.write_str("Aptos transfer recipient is not allowed"),
            Self::TotalExceedsLimit { total_octas } => write!(
                f,
                "Aptos transfer plus maximum gas cost ({total_octas} octas) exceeds 10 APT"
            ),
        }
    }
}

// Extend supported wire shapes here, preserving Aptos variant indices and field order.
// New shapes still need domain separation, full BCS consumption, sender binding,
// and checked arithmetic before reaching business policy.
pub(crate) fn parse_and_validate_aptos_transaction(
    signing_message: &[u8],
    sender: Address,
) -> Result<ValidatedAptosTransaction, AptosRejectReason> {
    use AptosRejectReason as Reject;
    let prefix = Sha3_256::digest(b"APTOS::RawTransaction");
    let bytes = signing_message
        .strip_prefix(prefix.as_slice())
        .ok_or(Reject::InvalidSigningPrefix)?;
    // from_bytes requires complete consumption; signed envelopes/trailing bytes fail.
    let transaction: RawTransaction =
        bcs::from_bytes(bytes).map_err(|_| Reject::InvalidTransactionBcs)?;
    if transaction.sender != sender {
        return Err(Reject::SenderMismatch);
    }
    let entry = &transaction.payload.0;
    let mut framework = [0; 32];
    framework[31] = 1;
    if entry.module.address != Address(framework)
        || entry.module.name != "aptos_account"
        || entry.function != "transfer"
    {
        return Err(Reject::UnsupportedFunction);
    }
    let [recipient, amount] = entry.args.as_slice() else {
        return Err(Reject::InvalidArguments);
    };
    let recipient: Address = bcs::from_bytes(recipient).map_err(|_| Reject::InvalidArguments)?;
    let transferred_octas: u64 = bcs::from_bytes(amount).map_err(|_| Reject::InvalidArguments)?;
    let maximum_gas_cost_octas = transaction
        .max_gas_amount
        .checked_mul(transaction.gas_unit_price)
        .ok_or(Reject::ArithmeticOverflow)?;
    let total_octas = transferred_octas
        .checked_add(maximum_gas_cost_octas)
        .ok_or(Reject::ArithmeticOverflow)?;
    Ok(ValidatedAptosTransaction {
        transaction,
        summary: TransferSummary {
            recipient,
            transferred_octas,
            maximum_gas_cost_octas,
            total_octas,
        },
    })
}

/// Business-policy extension point; parsing and checked arithmetic have already succeeded.
/// Add recipient, spending, or transaction-field checks (such as chain ID) here.
/// All checks must pass; keep structural validation in the parser above.
pub(crate) fn evaluate_aptos_transfer_policy(
    _transaction: &RawTransaction,
    summary: &TransferSummary,
) -> Result<(), AptosRejectReason> {
    if summary.recipient != ALLOWED_RECIPIENT {
        return Err(AptosRejectReason::RecipientNotAllowed);
    }
    if summary.total_octas > MAX_TOTAL_OCTAS {
        return Err(AptosRejectReason::TotalExceedsLimit {
            total_octas: summary.total_octas,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sender() -> Address {
        Address([0; 32])
    }
    pub(crate) fn other_sender() -> Address {
        Address([1; 32])
    }

    pub(crate) fn transaction() -> RawTransaction {
        let mut framework = [0; 32];
        framework[31] = 1;
        RawTransaction {
            sender: sender(),
            sequence_number: 42,
            payload: EntryFunctionPayload(EntryFunction {
                module: ModuleId {
                    address: Address(framework),
                    name: "aptos_account".into(),
                },
                function: "transfer".into(),
                type_args: vec![],
                args: vec![[7; 32].to_vec(), 100_000_000u64.to_le_bytes().to_vec()],
            }),
            max_gas_amount: 2_000,
            gas_unit_price: 100,
            expiration_timestamp_secs: 2_000_000_000,
            chain_id: 2,
        }
    }

    pub(crate) fn signing_message(transaction: &RawTransaction) -> Vec<u8> {
        let mut message = Sha3_256::digest(b"APTOS::RawTransaction").to_vec();
        message.extend(bcs::to_bytes(transaction).expect("fixture serializes"));
        message
    }

    pub(crate) fn over_limit_message() -> Vec<u8> {
        let mut tx = transaction();
        tx.max_gas_amount = 10_000_000;
        signing_message(&tx)
    }

    #[test]
    fn matches_complete_sdk_reference_transaction_and_summary() {
        for (fixture, amount, total) in [
            (
                include_str!("../tests/fixtures/aptos-transfer.hex"),
                100_000_000u64,
                100_200_000,
            ),
            (
                include_str!("../tests/fixtures/aptos-transfer-at-cap.hex"),
                999_800_000,
                MAX_TOTAL_OCTAS,
            ),
        ] {
            let reference = qos_hex::decode(fixture.trim()).expect("SDK hex");
            let mut expected_transaction = transaction();
            expected_transaction.payload.0.args[1] = amount.to_le_bytes().to_vec();
            assert_eq!(signing_message(&expected_transaction), reference);
            assert_eq!(
                parse_and_validate_aptos_transaction(&reference, sender()),
                Ok(ValidatedAptosTransaction {
                    transaction: expected_transaction,
                    summary: TransferSummary {
                        recipient: ALLOWED_RECIPIENT,
                        transferred_octas: amount,
                        maximum_gas_cost_octas: 200_000,
                        total_octas: total,
                    },
                })
            );
        }
    }

    #[test]
    fn applies_recipient_and_inclusive_total_cap_after_structural_validation() {
        for (amount, expected) in [
            (100_000_000u64, Ok(())),
            (999_800_000, Ok(())),
            (
                999_800_001,
                Err(AptosRejectReason::TotalExceedsLimit {
                    total_octas: MAX_TOTAL_OCTAS + 1,
                }),
            ),
        ] {
            let mut tx = transaction();
            tx.payload.0.args[1] = amount.to_le_bytes().to_vec();
            let validated = parse_and_validate_aptos_transaction(&signing_message(&tx), sender())
                .expect("valid structure");
            assert_eq!(
                evaluate_aptos_transfer_policy(&validated.transaction, &validated.summary),
                expected
            );
        }
        let mut tx = transaction();
        tx.payload.0.args[0] = [8; 32].to_vec();
        let validated = parse_and_validate_aptos_transaction(&signing_message(&tx), sender())
            .expect("valid structure");
        assert_eq!(
            evaluate_aptos_transfer_policy(&validated.transaction, &validated.summary),
            Err(AptosRejectReason::RecipientNotAllowed)
        );
    }

    #[test]
    fn rejects_sender_mismatch_and_both_arithmetic_overflows() {
        assert_eq!(
            parse_and_validate_aptos_transaction(&signing_message(&transaction()), other_sender()),
            Err(AptosRejectReason::SenderMismatch)
        );
        for (amount, max_gas, price) in [(0u64, u64::MAX, 2), (1, u64::MAX, 1)] {
            let mut tx = transaction();
            tx.payload.0.args[1] = amount.to_le_bytes().to_vec();
            tx.max_gas_amount = max_gas;
            tx.gas_unit_price = price;
            assert_eq!(
                parse_and_validate_aptos_transaction(&signing_message(&tx), sender()),
                Err(AptosRejectReason::ArithmeticOverflow)
            );
        }
    }

    #[test]
    fn rejects_missing_wrong_and_data_domains_and_digests() {
        let message = signing_message(&transaction());
        let mut wrong = message.clone();
        wrong[0] ^= 1;
        let mut with_data = Sha3_256::digest(b"APTOS::RawTransactionWithData").to_vec();
        with_data.extend_from_slice(&message[32..]);
        for bytes in [
            vec![],
            message[32..].to_vec(),
            Sha3_256::digest(&message).to_vec(),
            wrong,
            with_data,
        ] {
            assert_eq!(
                parse_and_validate_aptos_transaction(&bytes, sender()),
                Err(AptosRejectReason::InvalidSigningPrefix)
            );
        }
        assert_eq!(
            parse_and_validate_aptos_transaction(&message[..32], sender()),
            Err(AptosRejectReason::InvalidTransactionBcs)
        );
    }

    #[test]
    fn rejects_every_truncation_trailing_bytes_and_signed_envelopes() {
        let message = signing_message(&transaction());
        for end in 32..message.len() {
            assert_eq!(
                parse_and_validate_aptos_transaction(&message[..end], sender()),
                Err(AptosRejectReason::InvalidTransactionBcs),
                "length {end}"
            );
        }
        let mut authenticator = vec![0, 32]; // Ed25519 variant and public-key byte-vector length.
        authenticator.extend([0; 32]);
        authenticator.push(64); // Signature byte-vector length.
        authenticator.extend([0; 64]);
        for suffix in [vec![0], authenticator] {
            let mut bytes = message.clone();
            bytes.extend(suffix);
            assert_eq!(
                parse_and_validate_aptos_transaction(&bytes, sender()),
                Err(AptosRejectReason::InvalidTransactionBcs)
            );
        }
    }

    #[test]
    fn rejects_unsupported_variants_and_nonempty_type_arguments() {
        let message = signing_message(&transaction());
        for tag in [0, 1, 3, 4, 127] {
            let mut bytes = message.clone();
            bytes[72] = tag;
            assert_eq!(
                parse_and_validate_aptos_transaction(&bytes, sender()),
                Err(AptosRejectReason::InvalidTransactionBcs)
            );
        }
        // domain + sender + sequence + payload tag + module address + two BCS strings.
        let type_arg_offset =
            32 + 32 + 8 + 1 + 32 + 1 + "aptos_account".len() + 1 + "transfer".len();
        let mut bytes = message;
        bytes.splice(type_arg_offset..=type_arg_offset, [1, 1]); // one TypeTag::U8
        assert_eq!(
            parse_and_validate_aptos_transaction(&bytes, sender()),
            Err(AptosRejectReason::InvalidTransactionBcs)
        );
    }

    #[test]
    fn rejects_other_functions_and_malformed_arguments() {
        for field in 0..3 {
            let mut tx = transaction();
            match field {
                0 => tx.payload.0.module.address = other_sender(),
                1 => tx.payload.0.module.name = "coin".into(),
                _ => tx.payload.0.function = "other".into(),
            }
            assert_eq!(
                parse_and_validate_aptos_transaction(&signing_message(&tx), sender()),
                Err(AptosRejectReason::UnsupportedFunction)
            );
        }
        for args in [
            vec![],
            vec![vec![7; 32]],
            vec![vec![7; 32], vec![0; 8], vec![]],
            vec![vec![7; 31], vec![0; 8]],
            vec![vec![7; 33], vec![0; 8]],
            vec![vec![7; 32], vec![0; 7]],
            vec![vec![7; 32], vec![0; 9]],
        ] {
            let mut tx = transaction();
            tx.payload.0.args = args;
            assert_eq!(
                parse_and_validate_aptos_transaction(&signing_message(&tx), sender()),
                Err(AptosRejectReason::InvalidArguments)
            );
        }
    }
}
