//! Key derivation — the trust crux.
//!
//! Inside the enclave, QOS exposes the quorum master seed (stable across
//! deploys) at [`QUORUM_KEY_PATH`]. We HKDF-derive two independent P-256 API
//! keys from it: `programmatic` and `admin`. Because the seed is stable, the
//! derived public keys are stable too, so they can be registered as Turnkey
//! API users exactly once (via `GET /pubkeys`).
//!
//! Format requirements Turnkey enforces (pinned by the tests below):
//!   - public key: compressed SEC1 P-256, 33 bytes, `02`/`03` prefix, hex.
//!   - (signing format lives in `stamp.rs` — ECDSA-P256 / SHA-256 / DER.)

use std::path::Path;

use hkdf::Hkdf;
use p256::SecretKey;
use p256::ecdsa::SigningKey;
use sha2::Sha512;

/// Path inside the enclave where QOS writes the hex-encoded 32-byte quorum seed.
pub const QUORUM_KEY_PATH: &str = "/qos.quorum.key";

/// HKDF salts. These domain-separate the two keys so they're independent, and
/// are versioned so the derivation can be rotated without colliding with old keys.
const PROG_SALT: &[u8] = b"tvc-cosign-programmatic-v1";
const ADMIN_SALT: &[u8] = b"tvc-cosign-admin-v1";

/// Insecure fixed seed used only when [`QUORUM_KEY_PATH`] is absent (i.e. running
/// outside an enclave, in dev/CI). Keys derived from it are NOT secret.
const DEV_SEED: [u8; 32] = [0x11; 32];

/// A single derived Turnkey API key.
pub struct ApiKey {
    signing_key: SigningKey,
}

impl ApiKey {
    /// The P-256 signing key, used to produce Turnkey stamps.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Compressed SEC1 public key as lowercase hex — the exact form Turnkey
    /// registers as an `API_KEY_CURVE_P256` user public key.
    pub fn public_key_hex(&self) -> String {
        let point = self.signing_key.verifying_key().to_sec1_point(true);
        hex::encode(point.as_bytes())
    }
}

/// The pair of keys derived for this enclave.
pub struct KeySet {
    pub programmatic: ApiKey,
    pub admin: ApiKey,
}

impl KeySet {
    /// Derive both keys from a 32-byte quorum seed.
    pub fn derive(quorum_seed: &[u8; 32]) -> Self {
        KeySet {
            programmatic: derive_key(quorum_seed, PROG_SALT),
            admin: derive_key(quorum_seed, ADMIN_SALT),
        }
    }

    /// Load the quorum seed from the enclave and derive both keys. Outside an
    /// enclave the seed file is absent, so we fall back to [`DEV_SEED`] and warn.
    pub fn load() -> Self {
        match read_quorum_seed(Path::new(QUORUM_KEY_PATH)) {
            Some(seed) => {
                println!("keys: derived from quorum seed at {QUORUM_KEY_PATH}");
                Self::derive(&seed)
            }
            None => {
                eprintln!(
                    "keys: WARNING {QUORUM_KEY_PATH} not found — using INSECURE dev seed \
                     (not running in an enclave)"
                );
                Self::derive(&DEV_SEED)
            }
        }
    }
}

/// HKDF-SHA512-expand the quorum seed into a 32-byte P-256 scalar, keyed by `salt`.
fn derive_key(seed: &[u8; 32], salt: &[u8]) -> ApiKey {
    let hk = Hkdf::<Sha512>::new(Some(salt), seed);
    let mut okm = [0u8; 32];
    hk.expand(&[], &mut okm)
        .expect("32 bytes is well under HKDF-SHA512's output limit");
    let secret =
        SecretKey::from_slice(&okm).expect("HKDF output is a valid P-256 scalar (overwhelmingly)");
    ApiKey {
        signing_key: secret.into(),
    }
}

/// Read and hex-decode the quorum seed. Returns `None` if the file is missing or
/// malformed, so callers can fall back gracefully outside an enclave.
fn read_quorum_seed(path: &Path) -> Option<[u8; 32]> {
    let contents = std::fs::read_to_string(path).ok()?;
    let bytes = hex::decode(contents.trim()).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; 32] = [0xAB; 32];
    const SEED_B: [u8; 32] = [0xCD; 32];

    #[test]
    fn derivation_is_deterministic() {
        let k1 = KeySet::derive(&SEED_A);
        let k2 = KeySet::derive(&SEED_A);
        assert_eq!(
            k1.programmatic.public_key_hex(),
            k2.programmatic.public_key_hex()
        );
        assert_eq!(k1.admin.public_key_hex(), k2.admin.public_key_hex());
    }

    #[test]
    fn prog_and_admin_are_independent() {
        let k = KeySet::derive(&SEED_A);
        assert_ne!(k.programmatic.public_key_hex(), k.admin.public_key_hex());
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let a = KeySet::derive(&SEED_A);
        let b = KeySet::derive(&SEED_B);
        assert_ne!(
            a.programmatic.public_key_hex(),
            b.programmatic.public_key_hex()
        );
    }

    #[test]
    fn public_key_is_compressed_sec1() {
        let k = KeySet::derive(&SEED_A);
        for hexkey in [k.programmatic.public_key_hex(), k.admin.public_key_hex()] {
            let bytes = hex::decode(&hexkey).unwrap();
            assert_eq!(bytes.len(), 33, "compressed SEC1 is 33 bytes");
            assert!(
                bytes[0] == 0x02 || bytes[0] == 0x03,
                "compressed SEC1 prefix must be 02 or 03, got {:#04x}",
                bytes[0]
            );
        }
    }

    /// Known-answer regression guard: if the derivation ever changes, the
    /// registered Turnkey pubkeys would silently break. Pin the exact output.
    #[test]
    fn known_answer_pins_derivation() {
        let k = KeySet::derive(&SEED_A);
        assert_eq!(
            k.programmatic.public_key_hex(),
            "0240e6b810d86b5b378d4379680c28b7a6b409ce02bc8b9bd07779f03e4eed163b",
            "programmatic pubkey drifted"
        );
        assert_eq!(
            k.admin.public_key_hex(),
            "025090879edf953832e696931b201502980e6bfa73ee70d3738eab1f64f549c85e",
            "admin pubkey drifted"
        );
    }
}
