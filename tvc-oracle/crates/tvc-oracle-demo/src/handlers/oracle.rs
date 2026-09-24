use crate::{
    config::{ETH_USD_TEMPLATE_ID, SOURCE_AIRNODE},
    response::AppError,
    state::AppState,
};
use axum::{Json, extract::State};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

const COINGECKO_SIGNED_API_ROOT: &str = "https://signed-api.coingecko.com";
const SOURCE_NAME: &str = "CoinGecko";
const PAIR: &str = "ETH/USD";
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationResponse {
    certified_airnodes: Vec<String>,
}

#[derive(Deserialize)]
struct SignedApiResponse {
    data: HashMap<String, SignedApiObservation>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedApiObservation {
    airnode: String,
    encoded_value: String,
    signature: String,
    template_id: String,
    timestamp: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifiedObservation {
    pub(crate) source: &'static str,
    pub(crate) pair: &'static str,
    pub(crate) price_usd: String,
    pub(crate) price_usd_e18: String,
    pub(crate) source_timestamp: u64,
    pub(crate) airnode: String,
    pub(crate) template_id: String,
    pub(crate) beacon_id: String,
    pub(crate) encoded_value: String,
    pub(crate) signature: String,
    pub(crate) payload_hash: String,
    pub(crate) verified: bool,
}

pub(crate) async fn signed_eth_usd_observation(
    State(state): State<AppState>,
) -> Result<Json<VerifiedObservation>, AppError> {
    Ok(Json(fetch_verified_observation(&state).await?))
}

pub(crate) async fn fetch_verified_observation(
    state: &AppState,
) -> Result<VerifiedObservation, AppError> {
    let certification: CertificationResponse = fetch_json(
        state,
        COINGECKO_SIGNED_API_ROOT,
        "CoinGecko signer certification",
    )
    .await?;
    if !certification
        .certified_airnodes
        .iter()
        .any(|airnode| airnode.eq_ignore_ascii_case(SOURCE_AIRNODE))
    {
        return Err(AppError::bad_gateway(
            "configured CoinGecko signer is not currently certified",
        ));
    }

    let url = format!("{COINGECKO_SIGNED_API_ROOT}/public/{SOURCE_AIRNODE}");
    let response: SignedApiResponse =
        fetch_json(state, &url, "CoinGecko signed observations").await?;

    let expected_beacon_id = beacon_id(SOURCE_AIRNODE, ETH_USD_TEMPLATE_ID)
        .map_err(|e| AppError::internal(format!("invalid oracle configuration: {e}")))?;
    let observation = response
        .data
        .get(&expected_beacon_id)
        .ok_or_else(|| AppError::bad_gateway("CoinGecko response is missing ETH/USD data"))?;
    let verified = verify_observation(observation)
        .map_err(|e| AppError::bad_gateway(format!("invalid CoinGecko observation: {e}")))?;

    Ok(verified)
}

async fn fetch_json<T>(state: &AppState, url: &str, description: &str) -> Result<T, AppError>
where
    T: serde::de::DeserializeOwned,
{
    let response = state.http_client.get(url).send().await.map_err(|e| {
        tracing::error!("{description} request failed: {e}");
        AppError::bad_gateway(format!("failed to reach {description}"))
    })?;
    let status = response.status();
    if !status.is_success() {
        tracing::error!("{description} returned {status}");
        return Err(AppError::bad_gateway(format!(
            "{description} returned HTTP {}",
            status.as_u16()
        )));
    }
    response.json().await.map_err(|e| {
        tracing::error!("failed to parse {description}: {e}");
        AppError::bad_gateway(format!("failed to parse {description}"))
    })
}

fn verify_observation(observation: &SignedApiObservation) -> Result<VerifiedObservation, String> {
    if !observation.airnode.eq_ignore_ascii_case(SOURCE_AIRNODE) {
        return Err("unexpected signing address".to_owned());
    }
    if !observation
        .template_id
        .eq_ignore_ascii_case(ETH_USD_TEMPLATE_ID)
    {
        return Err("unexpected template ID".to_owned());
    }

    let template_id = decode_fixed::<32>(&observation.template_id, "template ID")?;
    let encoded_value = decode_fixed::<32>(&observation.encoded_value, "encoded value")?;
    let timestamp = observation
        .timestamp
        .parse::<u64>()
        .map_err(|_| "invalid timestamp".to_owned())?;
    let signature_bytes = decode_fixed::<65>(&observation.signature, "signature")?;

    let mut encoded_timestamp = [0_u8; 32];
    encoded_timestamp[24..].copy_from_slice(&timestamp.to_be_bytes());
    let payload_hash = keccak256(&[&template_id, &encoded_timestamp, &encoded_value]);
    let ethereum_message_hash = keccak256(&[b"\x19Ethereum Signed Message:\n32", &payload_hash]);
    let recovered_address = recover_ethereum_address(ethereum_message_hash, signature_bytes)?;
    let expected_address = decode_fixed::<20>(SOURCE_AIRNODE, "source Airnode")?;
    if recovered_address != expected_address {
        return Err(format!(
            "signature recovered {}, expected {}",
            encode_hex(&recovered_address),
            SOURCE_AIRNODE
        ));
    }

    let price = decode_positive_int256_as_u128(encoded_value)?;
    let beacon_id = keccak256(&[&expected_address, &template_id]);

    Ok(VerifiedObservation {
        source: SOURCE_NAME,
        pair: PAIR,
        price_usd: format_e18(price),
        price_usd_e18: price.to_string(),
        source_timestamp: timestamp,
        airnode: observation.airnode.clone(),
        template_id: observation.template_id.clone(),
        beacon_id: encode_hex(&beacon_id),
        encoded_value: observation.encoded_value.clone(),
        signature: observation.signature.clone(),
        payload_hash: encode_hex(&payload_hash),
        verified: true,
    })
}

fn recover_ethereum_address(
    digest: [u8; 32],
    signature_bytes: [u8; 65],
) -> Result<[u8; 20], String> {
    let signature = Signature::from_slice(&signature_bytes[..64])
        .map_err(|e| format!("malformed signature: {e}"))?;
    let recovery_byte = match signature_bytes[64] {
        27 | 28 => signature_bytes[64] - 27,
        0 | 1 => signature_bytes[64],
        _ => return Err("invalid signature recovery ID".to_owned()),
    };
    let recovery_id = RecoveryId::from_byte(recovery_byte)
        .ok_or_else(|| "invalid signature recovery ID".to_owned())?;
    let verifying_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|e| format!("signature recovery failed: {e}"))?;
    let public_key = verifying_key.to_encoded_point(false);
    let public_key_hash = keccak256(&[&public_key.as_bytes()[1..]]);
    let mut address = [0_u8; 20];
    address.copy_from_slice(&public_key_hash[12..]);
    Ok(address)
}

fn beacon_id(airnode: &str, template_id: &str) -> Result<String, String> {
    let airnode = decode_fixed::<20>(airnode, "source Airnode")?;
    let template_id = decode_fixed::<32>(template_id, "template ID")?;
    Ok(encode_hex(&keccak256(&[&airnode, &template_id])))
}

fn decode_positive_int256_as_u128(encoded: [u8; 32]) -> Result<u128, String> {
    if encoded[0] & 0x80 != 0 {
        return Err("price must be positive".to_owned());
    }
    if encoded[..16].iter().any(|byte| *byte != 0) {
        return Err("price exceeds supported range".to_owned());
    }
    let mut lower = [0_u8; 16];
    lower.copy_from_slice(&encoded[16..]);
    let value = u128::from_be_bytes(lower);
    if value == 0 {
        return Err("price must be positive".to_owned());
    }
    Ok(value)
}

fn format_e18(value: u128) -> String {
    let whole = value / 1_000_000_000_000_000_000;
    let fractional = value % 1_000_000_000_000_000_000;
    if fractional == 0 {
        return whole.to_string();
    }
    let fractional = format!("{fractional:018}").trim_end_matches('0').to_owned();
    format!("{whole}.{fractional}")
}

pub(crate) fn decode_fixed<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let decoded = qos_hex::decode(value).map_err(|e| format!("invalid {name} hex: {e:?}"))?;
    decoded
        .try_into()
        .map_err(|_| format!("invalid {name} length"))
}

fn encode_hex(value: &[u8]) -> String {
    format!("0x{}", qos_hex::encode(value))
}

fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn fixture() -> SignedApiObservation {
        SignedApiObservation {
            airnode: SOURCE_AIRNODE.to_owned(),
            encoded_value:
                "0x000000000000000000000000000000000000000000000081a0fb87b871530000"
                    .to_owned(),
            signature:
                "0x6a157125cc065e38c66d6b978f8897d7693282462f041fb68bbdd49cbc5b8322143c59e8ac68aacdb2533a5247e0fb50601a0bbd7f8c1e4a7e5627d685dbb3361c"
                    .to_owned(),
            template_id: ETH_USD_TEMPLATE_ID.to_owned(),
            timestamp: "1788381825".to_owned(),
        }
    }

    #[test]
    fn verifies_real_coingecko_observation() {
        let verified = verify_observation(&fixture()).expect("fixture should verify");

        assert_eq!(verified.price_usd, "2391.23");
        assert_eq!(verified.price_usd_e18, "2391230000000000000000");
        assert_eq!(verified.source_timestamp, 1_788_381_825);
        assert_eq!(
            verified.beacon_id,
            "0x478a1bccb55fd03b0ef6a401fdfc86431e9abd7cb6ef456b505d9a13fbcb324d"
        );
        assert!(verified.verified);
    }

    #[test]
    fn rejects_tampered_value() {
        let mut observation = fixture();
        observation.encoded_value =
            "0x000000000000000000000000000000000000000000000081a0fb87b871530001".to_owned();

        let error = verify_observation(&observation).expect_err("tampering should fail");
        assert!(error.contains("signature recovered"));
    }

    #[test]
    fn rejects_unexpected_template() {
        let mut observation = fixture();
        observation.template_id = encode_hex(&keccak256(&[b"BTC/USD"]));

        assert_eq!(
            verify_observation(&observation).expect_err("wrong template should fail"),
            "unexpected template ID"
        );
    }

    #[test]
    fn formats_e18_without_float_rounding() {
        assert_eq!(format_e18(2_391_230_000_000_000_000_000), "2391.23");
        assert_eq!(format_e18(1_000_000_000_000_000_000), "1");
        assert_eq!(format_e18(1), "0.000000000000000001");
    }
}
