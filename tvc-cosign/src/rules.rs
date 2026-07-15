//! The classification engine: decide whether an unsigned transaction is
//! `PROGRAMMATIC` (auto-signable), `ADMIN` (needs human consensus), or `REJECT`.
//!
//! Rules are config-driven (see `rules.example.toml`) so the customer can tune
//! allowlists and caps without code changes. In production the ruleset is baked
//! into the reproducible enclave image, so it's covered by the image measurement.

use std::collections::HashSet;

use alloy_primitives::{Address, U256};
use serde::Deserialize;

use crate::tx::ParsedTx;

/// ERC-20 `transfer(address,uint256)` selector (`keccak256(...)[..4]`).
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Ruleset compiled into the binary at build time. TVC runs only the pivot binary,
/// so the ruleset ships inside it rather than as a file in the image.
const EMBEDDED_RULES_TOML: &str = include_str!("../rules.toml");

/// How a transaction is routed. Serialized as `PROGRAMMATIC` / `ADMIN` / `REJECT`.
#[derive(serde::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    Programmatic,
    Admin,
    Reject,
}

/// The active ruleset, in runtime form (typed, deduplicated).
pub struct Ruleset {
    allowed_signers: HashSet<Address>,
    allowed_tokens: HashSet<Address>,
    allowed_recipients: HashSet<Address>,
    max_amount: U256,
    admin_selectors: HashSet<[u8; 4]>,
}

impl Ruleset {
    /// Load and validate a ruleset from a TOML file (local-dev override only; see
    /// [`Ruleset::embedded`]).
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        let raw: RawRuleset = toml::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
        raw.into_ruleset()
    }

    /// The ruleset compiled into the binary, covered by the attested
    /// `expectedPivotDigest`. This is what a real TVC deployment enforces.
    pub fn embedded() -> Result<Self, String> {
        let raw: RawRuleset = toml::from_str(EMBEDDED_RULES_TOML)
            .map_err(|e| format!("parse embedded rules.toml: {e}"))?;
        raw.into_ruleset()
    }
}

/// Classify a parsed transaction against the ruleset.
///
/// `signer` is the wallet the transaction would be signed by (`signWith`). It is
/// a global gate: the enclave only stamps for allowlisted wallets, whatever the
/// classification.
pub fn classify(signer: Address, tx: &ParsedTx, rules: &Ruleset) -> Classification {
    if !rules.allowed_signers.contains(&signer) {
        return Classification::Reject;
    }

    if tx.to.is_none() {
        // Contract creation (`to == None`) is out of scope for this POC. Reject it
        // before the selector checks: otherwise initcode whose first 4 bytes happen
        // to match an admin selector would misclassify as ADMIN.
        return Classification::Reject;
    }

    let Some(selector) = tx.selector() else {
        // No calldata (e.g. a native transfer) — out of scope for this POC.
        return Classification::Reject;
    };

    if selector == TRANSFER_SELECTOR {
        return classify_transfer(tx, rules);
    }
    if rules.admin_selectors.contains(&selector) {
        return Classification::Admin;
    }
    Classification::Reject
}

/// An ERC-20 `transfer` is PROGRAMMATIC only if the token, recipient, and amount
/// all pass the allowlists/cap; otherwise REJECT.
fn classify_transfer(tx: &ParsedTx, rules: &Ruleset) -> Classification {
    // A token transfer should not also move native ETH.
    if !tx.value.is_zero() {
        return Classification::Reject;
    }
    let Some(token) = tx.to else {
        return Classification::Reject;
    };
    if !rules.allowed_tokens.contains(&token) {
        return Classification::Reject;
    }
    let Some((recipient, amount)) = decode_transfer_args(&tx.input) else {
        return Classification::Reject;
    };
    if !rules.allowed_recipients.contains(&recipient) || amount > rules.max_amount {
        return Classification::Reject;
    }
    Classification::Programmatic
}

/// Decode `transfer(address,uint256)` args: a 32-byte right-aligned address word
/// followed by a 32-byte amount. Rejects non-canonical (non-zero-padded) addresses.
fn decode_transfer_args(input: &[u8]) -> Option<(Address, U256)> {
    // 4 (selector) + 32 (address) + 32 (amount)
    if input.len() != 68 {
        return None;
    }
    let (addr_word, amount_word) = input[4..].split_at(32);
    if addr_word[..12].iter().any(|&b| b != 0) {
        return None; // address must be zero-padded in its 32-byte word
    }
    let recipient = Address::from_slice(&addr_word[12..]);
    let amount = U256::from_be_slice(amount_word);
    Some((recipient, amount))
}

// --- config deserialization (raw TOML shape -> runtime Ruleset) ---

#[derive(Deserialize)]
struct RawRuleset {
    /// Wallets (`signWith` targets) this deployment is permitted to sign for.
    #[serde(default)]
    allowed_signers: Vec<Address>,
    programmatic: RawProgrammatic,
    #[serde(default)]
    admin: RawAdmin,
}

#[derive(Deserialize)]
struct RawProgrammatic {
    #[serde(default)]
    allowed_tokens: Vec<Address>,
    #[serde(default)]
    allowed_recipients: Vec<Address>,
    /// Max transfer amount as a decimal (or `0x`-hex) string, so it can exceed i64.
    max_amount: String,
}

#[derive(Deserialize, Default)]
struct RawAdmin {
    #[serde(default)]
    selectors: Vec<String>,
}

impl RawRuleset {
    fn into_ruleset(self) -> Result<Ruleset, String> {
        let max_amount = self
            .programmatic
            .max_amount
            .parse::<U256>()
            .map_err(|e| format!("invalid max_amount: {e}"))?;

        let admin_selectors = self
            .admin
            .selectors
            .iter()
            .map(|s| parse_selector(s))
            .collect::<Result<HashSet<_>, _>>()?;

        Ok(Ruleset {
            allowed_signers: self.allowed_signers.into_iter().collect(),
            allowed_tokens: self.programmatic.allowed_tokens.into_iter().collect(),
            allowed_recipients: self.programmatic.allowed_recipients.into_iter().collect(),
            max_amount,
            admin_selectors,
        })
    }
}

/// Parse a 4-byte selector like `"0x12345678"`.
fn parse_selector(s: &str) -> Result<[u8; 4], String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex).map_err(|e| format!("invalid selector {s}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("selector {s} must be exactly 4 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, U256, address};

    const SIGNER: Address = address!("00000000000000000000000000000000000000a1");
    const TOKEN: Address = address!("1111111111111111111111111111111111111111");
    const RECIPIENT: Address = address!("00000000000000000000000000000000000000ff");

    fn ruleset_toml() -> Ruleset {
        let toml = r#"
            allowed_signers = ["0x00000000000000000000000000000000000000a1"]

            [programmatic]
            allowed_tokens = ["0x1111111111111111111111111111111111111111"]
            allowed_recipients = ["0x00000000000000000000000000000000000000ff"]
            max_amount = "1000"

            [admin]
            selectors = ["0x12345678"]
        "#;
        let raw: RawRuleset = toml::from_str(toml).unwrap();
        raw.into_ruleset().unwrap()
    }

    fn transfer_tx(token: Address, recipient: Address, amount: u64) -> ParsedTx {
        let mut input = vec![0xa9, 0x05, 0x9c, 0xbb];
        input.extend_from_slice(&[0u8; 12]);
        input.extend_from_slice(recipient.as_slice());
        input.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
        ParsedTx {
            to: Some(token),
            value: U256::ZERO,
            input: Bytes::from(input),
        }
    }

    #[test]
    fn allowlisted_transfer_under_cap_is_programmatic() {
        let tx = transfer_tx(TOKEN, RECIPIENT, 500);
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Programmatic
        );
    }

    #[test]
    fn transfer_over_cap_is_rejected() {
        let tx = transfer_tx(TOKEN, RECIPIENT, 5000);
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Reject
        );
    }

    #[test]
    fn transfer_to_unlisted_recipient_is_rejected() {
        let other = address!("00000000000000000000000000000000000000ee");
        let tx = transfer_tx(TOKEN, other, 100);
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Reject
        );
    }

    #[test]
    fn transfer_of_unlisted_token_is_rejected() {
        let other = address!("2222222222222222222222222222222222222222");
        let tx = transfer_tx(other, RECIPIENT, 100);
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Reject
        );
    }

    #[test]
    fn admin_selector_routes_to_admin() {
        let tx = ParsedTx {
            to: Some(TOKEN),
            value: U256::ZERO,
            input: Bytes::from(vec![0x12, 0x34, 0x56, 0x78]),
        };
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Admin
        );
    }

    #[test]
    fn contract_creation_with_admin_selector_initcode_is_rejected() {
        // `to == None` is contract creation (out of scope). Even if the initcode's
        // first 4 bytes collide with an allowlisted admin selector, it must REJECT,
        // not route to ADMIN.
        let tx = ParsedTx {
            to: None,
            value: U256::ZERO,
            input: Bytes::from(vec![0x12, 0x34, 0x56, 0x78]),
        };
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Reject
        );
    }

    #[test]
    fn unknown_selector_is_rejected() {
        let tx = ParsedTx {
            to: Some(TOKEN),
            value: U256::ZERO,
            input: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
        };
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Reject
        );
    }

    #[test]
    fn no_calldata_is_rejected() {
        let tx = ParsedTx {
            to: Some(RECIPIENT),
            value: U256::from(1u64),
            input: Bytes::new(),
        };
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Reject
        );
    }

    #[test]
    fn transfer_with_trailing_calldata_is_rejected() {
        // Canonical transfer calldata is exactly 68 bytes; extra trailing bytes
        // are non-canonical and must not be auto-classified as PROGRAMMATIC.
        let mut tx = transfer_tx(TOKEN, RECIPIENT, 500);
        let mut input = tx.input.to_vec();
        input.push(0xff);
        tx.input = Bytes::from(input);
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Reject
        );
    }

    #[test]
    fn transfer_with_attached_eth_is_rejected() {
        let mut tx = transfer_tx(TOKEN, RECIPIENT, 100);
        tx.value = U256::from(1u64);
        assert_eq!(
            classify(SIGNER, &tx, &ruleset_toml()),
            Classification::Reject
        );
    }

    #[test]
    fn non_allowlisted_signer_is_rejected() {
        let other_signer = address!("00000000000000000000000000000000000000b2");
        let tx = transfer_tx(TOKEN, RECIPIENT, 500); // otherwise valid
        assert_eq!(
            classify(other_signer, &tx, &ruleset_toml()),
            Classification::Reject
        );
    }

    #[test]
    fn embedded_ruleset_parses() {
        // The ruleset compiled in via include_str! is what a deployment enforces,
        // so it must always be valid; a malformed rules.toml should fail here, not
        // silently at enclave startup.
        Ruleset::embedded().expect("embedded rules.toml parses");
    }
}
