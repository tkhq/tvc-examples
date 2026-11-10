//! Keys derived from the QOS seeds that an enclave exposes.
//!
//! - The quorum seed (`/qos.quorum.key`) is stable across deployments. An API
//!   key derived from it can be registered with Turnkey once, and only code
//!   running with the quorum key can stamp with it.
//! - The ephemeral seed (`/qos.ephemeral.key`) is new on every boot. The
//!   encrypt key derived from it is the one QOS attests in the Boot Proof, so
//!   an export to it can only be read inside that enclave.
//!
//! This module derives keys from seed bytes the caller already read. It never
//! reads files.

use hkdf::Hkdf;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, Kem};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::{ApiKey, SecretsError};

/// A 32-byte QOS master seed.
pub type Seed = Zeroizing<[u8; 32]>;

/// HKDF salt for the Turnkey API key derived from the quorum seed.
const API_KEY_SALT: &[u8] = b"tvc-github-broker-export-v1";
/// HKDF salt QOS uses for the encrypt key of a key set. It must match
/// `qos_p256`, because QOS attests the public key derived this way.
const QOS_ENCRYPT_SALT: &[u8] = b"qos_p256_encrypt";

/// A P-256 scalar from HKDF-SHA512 over `seed`, with `salt` and empty info.
fn derive_scalar(seed: &Seed, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
    let mut scalar = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha512>::new(Some(salt), &seed[..])
        .expand(&[], &mut scalar[..])
        .map_err(|_| SecretsError::InvalidApiKey("key derivation failed".into()))?;
    Ok(scalar)
}

/// Decode a 32-byte seed from the hex text of a QOS key file.
///
/// # Errors
///
/// Returns [`SecretsError::InvalidApiKey`] if the text is not 64 hex digits.
pub fn seed_from_hex(text: &str) -> Result<Seed, SecretsError> {
    let bytes = Zeroizing::new(
        hex::decode(text.trim())
            .map_err(|_| SecretsError::InvalidApiKey("seed is not hex".into()))?,
    );
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| SecretsError::InvalidApiKey("seed is not 32 bytes".into()))?;
    Ok(Zeroizing::new(seed))
}

impl ApiKey {
    /// The API key derived from the quorum seed.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::InvalidApiKey`] if the derived value is not a
    /// valid P-256 scalar.
    pub fn from_quorum_seed(seed: &Seed) -> Result<Self, SecretsError> {
        let scalar = derive_scalar(seed, API_KEY_SALT)?;
        Self::from_private_hex(&Zeroizing::new(hex::encode(&scalar[..])))
    }
}

/// The HPKE key pair for the export target, derived from the ephemeral seed.
pub(crate) fn target_key_pair(
    seed: &Seed,
) -> Result<
    (
        <DhP256HkdfSha256 as Kem>::PublicKey,
        <DhP256HkdfSha256 as Kem>::PrivateKey,
    ),
    SecretsError,
> {
    let invalid = || SecretsError::Verification("derived target key is invalid".into());
    let scalar = derive_scalar(seed, QOS_ENCRYPT_SALT)?;
    let secret = SecretKey::from_slice(&scalar[..]).map_err(|_| invalid())?;
    let private =
        <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&scalar[..]).map_err(|_| invalid())?;
    let public = <DhP256HkdfSha256 as Kem>::PublicKey::from_bytes(
        secret.public_key().to_encoded_point(false).as_bytes(),
    )
    .map_err(|_| invalid())?;
    Ok((public, private))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use hpke::Serializable;

    use super::*;

    fn seed(byte: u8) -> Seed {
        Zeroizing::new([byte; 32])
    }

    #[test]
    fn the_api_key_is_stable_and_depends_on_the_seed() {
        let a = ApiKey::from_quorum_seed(&seed(0xab)).unwrap();
        assert_eq!(
            a.public_hex(),
            ApiKey::from_quorum_seed(&seed(0xab)).unwrap().public_hex()
        );
        assert_ne!(
            a.public_hex(),
            ApiKey::from_quorum_seed(&seed(0xcd)).unwrap().public_hex()
        );
        let bytes = hex::decode(a.public_hex()).unwrap();
        assert_eq!(bytes.len(), 33);
        assert!(bytes[0] == 2 || bytes[0] == 3);
    }

    #[test]
    fn the_target_is_the_qos_encrypt_key_of_the_seed() {
        // The same construction as qos_p256's key set: HKDF-SHA512 with the
        // path as salt, read as a P-256 scalar.
        let s = seed(0xab);
        let (public, _) = target_key_pair(&s).unwrap();
        let scalar = derive_scalar(&s, b"qos_p256_encrypt").unwrap();
        let secret = p256::SecretKey::from_slice(&scalar[..]).unwrap();
        let expected = secret.public_key().to_encoded_point(false);
        assert_eq!(public.to_bytes().as_slice(), expected.as_bytes());
    }

    #[test]
    fn the_api_key_and_the_target_are_independent() {
        let s = seed(0xab);
        let api = derive_scalar(&s, API_KEY_SALT).unwrap();
        let target = derive_scalar(&s, QOS_ENCRYPT_SALT).unwrap();
        assert_ne!(api[..], target[..]);
    }

    #[test]
    fn seeds_must_be_32_hex_bytes() {
        assert!(seed_from_hex(&"ab".repeat(32)).is_ok());
        assert!(seed_from_hex(&format!(" {}\n", "ab".repeat(32))).is_ok());
        assert!(seed_from_hex(&"ab".repeat(31)).is_err());
        assert!(seed_from_hex("zz").is_err());
    }
}
