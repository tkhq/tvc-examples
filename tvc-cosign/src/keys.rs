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
use zeroize::Zeroizing;

/// Path inside the enclave where QOS writes the hex-encoded 32-byte quorum seed.
pub const QUORUM_KEY_PATH: &str = "/qos.quorum.key";

/// Path inside the enclave where QOS writes the hex-encoded ephemeral key. Like
/// the quorum key this is a 32-byte *master seed* (unique per boot, one per
/// replica), from which the sign/encrypt keys are sub-derived via the QOS KeySet
/// paths below. QOS attests the resulting public keys in the enclave's Boot
/// Proof, so [`EphemeralKey`] must reconstruct them exactly.
pub const EPHEMERAL_KEY_PATH: &str = "/qos.ephemeral.key";

/// HKDF salts for our two Turnkey API keys. These domain-separate the keys and
/// are versioned so the derivation can be rotated. Unlike the ephemeral key, we
/// *register* these public keys ourselves (they are not attested), so the salts
/// are ours to choose — validated live against Turnkey.
const PROG_SALT: &[u8] = b"tvc-cosign-programmatic-v1";
const ADMIN_SALT: &[u8] = b"tvc-cosign-admin-v1";

/// QOS KeySet sub-derivation paths — used as the HKDF-SHA512 salt over a master
/// seed. These MUST match `qos_p256/src/lib.rs`, because QOS attests the public
/// keys it derives this way; the ephemeral key reconstruction depends on it.
const QOS_SIGN_PATH: &[u8] = b"qos_p256_sign";
const QOS_ENCRYPT_PATH: &[u8] = b"qos_p256_encrypt";

/// Insecure fixed seed used only when [`QUORUM_KEY_PATH`] is absent (i.e. running
/// outside an enclave, in dev/CI). Keys derived from it are NOT secret.
const DEV_SEED: [u8; 32] = [0x11; 32];

/// Insecure fixed ephemeral master seed used only when [`EPHEMERAL_KEY_PATH`] is
/// absent. App Proofs signed with it are NOT attestable — dev/CI only.
const DEV_EPHEMERAL_SEED: [u8; 32] = [0x22; 32];

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

/// The enclave's per-boot ephemeral key, reconstructed from the QOS master seed
/// at [`EPHEMERAL_KEY_PATH`]. It signs App Proofs (see `proof.rs`); its public
/// half is attested in the enclave's Boot Proof, so the sign/encrypt keys are
/// sub-derived with the exact [`QOS_SIGN_PATH`]/[`QOS_ENCRYPT_PATH`] construction
/// QOS uses. Each of a TVC's replicas boots its own ephemeral key.
pub struct EphemeralKey {
    signing_key: SigningKey,
    /// Uncompressed SEC1 (`04‖X‖Y`) hex of the sign public key — the form that
    /// appears in the App Proof `publicKey` field.
    public_key_hex: String,
    /// The QOS KeySet hex used to look up this replica's Boot Proof: uncompressed
    /// encrypt pubkey ‖ uncompressed sign pubkey (130 bytes).
    boot_ephemeral_key_hex: String,
}

impl EphemeralKey {
    /// Reconstruct the ephemeral key from a 32-byte QOS master seed.
    pub fn derive(master_seed: &[u8; 32]) -> Self {
        let sign_key = derive_signing_key(master_seed, QOS_SIGN_PATH);
        let encrypt_key = derive_signing_key(master_seed, QOS_ENCRYPT_PATH);

        let sign_pub = uncompressed_sec1(&sign_key);
        let encrypt_pub = uncompressed_sec1(&encrypt_key);

        // Boot Proof lookup key = encryptPub ‖ signPub (matches qos_p256 KeySet).
        let mut keyset = encrypt_pub;
        keyset.extend_from_slice(&sign_pub);

        EphemeralKey {
            signing_key: sign_key,
            public_key_hex: hex::encode(&sign_pub),
            boot_ephemeral_key_hex: hex::encode(&keyset),
        }
    }

    /// Load the master seed from the enclave and reconstruct the key. Outside an
    /// enclave the file is absent, so we fall back to [`DEV_EPHEMERAL_SEED`] and
    /// warn — proofs then carry no attestation value.
    pub fn load() -> Self {
        match read_hex_seed(Path::new(EPHEMERAL_KEY_PATH)) {
            Some(seed) => {
                println!("keys: reconstructed ephemeral key from {EPHEMERAL_KEY_PATH}");
                Self::derive(&seed)
            }
            None => {
                eprintln!(
                    "keys: WARNING {EPHEMERAL_KEY_PATH} not found — using INSECURE dev ephemeral \
                     key (not running in an enclave)"
                );
                Self::derive(&DEV_EPHEMERAL_SEED)
            }
        }
    }

    /// The P-256 signing key used to sign App Proofs.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Uncompressed SEC1 hex of the sign public key (App Proof `publicKey`).
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// The QOS KeySet hex for Boot Proof lookup (`get_boot_proof`'s `ephemeralKey`).
    pub fn boot_ephemeral_key_hex(&self) -> &str {
        &self.boot_ephemeral_key_hex
    }
}

/// Uncompressed SEC1 encoding (`04‖X‖Y`, 65 bytes) of a signing key's public key.
fn uncompressed_sec1(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
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
        match read_hex_seed(Path::new(QUORUM_KEY_PATH)) {
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

/// HKDF-SHA512-expand a 32-byte seed into a P-256 signing key, keyed by `salt`.
/// The construction (extract with `salt`, expand with empty `info`) matches both
/// our own API-key derivation and QOS's KeySet sub-derivation.
fn derive_signing_key(seed: &[u8; 32], salt: &[u8]) -> SigningKey {
    let hk = Hkdf::<Sha512>::new(Some(salt), seed);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&[], &mut okm[..])
        .expect("32 bytes is well under HKDF-SHA512's output limit");
    let secret = SecretKey::from_slice(&okm[..])
        .expect("HKDF output is a valid P-256 scalar (overwhelmingly)");
    secret.into()
}

/// Derive one of our Turnkey API keys from the quorum seed.
fn derive_key(seed: &[u8; 32], salt: &[u8]) -> ApiKey {
    ApiKey {
        signing_key: derive_signing_key(seed, salt),
    }
}

/// Read and hex-decode a 32-byte hex seed file (`/qos.quorum.key` or
/// `/qos.ephemeral.key`). Returns `None` if the file is missing or malformed, so
/// callers can fall back gracefully outside an enclave.
fn read_hex_seed(path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    let contents = Zeroizing::new(std::fs::read_to_string(path).ok()?);
    let bytes = Zeroizing::new(hex::decode(contents.trim()).ok()?);
    Some(Zeroizing::new(bytes.as_slice().try_into().ok()?))
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

    #[test]
    fn ephemeral_sign_pubkey_is_uncompressed_sec1() {
        let e = EphemeralKey::derive(&SEED_A);
        let bytes = hex::decode(e.public_key_hex()).unwrap();
        assert_eq!(bytes.len(), 65, "uncompressed SEC1 is 65 bytes");
        assert_eq!(bytes[0], 0x04, "uncompressed SEC1 prefix must be 0x04");
    }

    #[test]
    fn boot_ephemeral_key_is_encrypt_then_sign_pubkeys() {
        let e = EphemeralKey::derive(&SEED_A);
        let keyset = hex::decode(e.boot_ephemeral_key_hex()).unwrap();
        // encryptPub (65) ‖ signPub (65) — matches the QOS KeySet layout.
        assert_eq!(keyset.len(), 130);
        assert_eq!(keyset[0], 0x04, "encrypt pubkey is uncompressed");
        assert_eq!(keyset[65], 0x04, "sign pubkey is uncompressed");
        // The sign half is exactly the App Proof public key.
        let sign_pub = hex::encode(&keyset[65..]);
        assert_eq!(sign_pub, e.public_key_hex());
    }

    #[test]
    fn ephemeral_derivation_is_deterministic() {
        assert_eq!(
            EphemeralKey::derive(&SEED_A).boot_ephemeral_key_hex(),
            EphemeralKey::derive(&SEED_A).boot_ephemeral_key_hex()
        );
    }

    /// Known-answer, cross-checked byte-for-byte against the production Go
    /// reference (tvc-chainalysis `buildBootEphemeralKey` / `qos_p256_sign`) for
    /// the seed `[0x22; 32]`. If this drifts, App Proofs stop linking to Boot
    /// Proofs — the whole verifiability chain silently breaks.
    #[test]
    fn ephemeral_matches_qos_reference() {
        let e = EphemeralKey::derive(&[0x22; 32]);
        assert_eq!(
            e.public_key_hex(),
            "049050ec6740957f5eefab0fdaf858bb33e0bd1e6c0f7128ad5c5cfc0f64db2877\
             891a0bf1d63c82630abc16adefff48cd0703956e2f265b82ea8df8a99ca58e89"
        );
        assert_eq!(
            e.boot_ephemeral_key_hex(),
            "04bd9e94d0358df8fec7d6d654cc66f46952f2b0f710f76e8478bc1620b32bb024\
             2a9d1a9dd3c7a5a71526c3bb3be749e4ced4f7d7344af33ef35d3824c8f58d09\
             049050ec6740957f5eefab0fdaf858bb33e0bd1e6c0f7128ad5c5cfc0f64db2877\
             891a0bf1d63c82630abc16adefff48cd0703956e2f265b82ea8df8a99ca58e89"
        );
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
