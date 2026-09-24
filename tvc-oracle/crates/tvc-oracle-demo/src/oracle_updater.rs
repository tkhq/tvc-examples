//! Autonomous CoinGecko-to-Sepolia oracle update loop.

use crate::{
    handlers::{decode_fixed, fetch_verified_observation},
    state::AppState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::{io, time::Duration};
use turnkey_client::generated::immutable::{
    activity::v1::SignTransactionIntentV2, common::v1::TransactionType,
};

const ORGANIZATION_ID: &str = "e4c1c7b7-bcad-4467-ac4c-f34447f4cdcd";
const SEPOLIA_RPC_URL: &str = "https://ethereum-sepolia-rpc.publicnode.com";
const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
const ORACLE_ADDRESS: &str = "0x9890Df3894EbF1dbCD8E69aA7fafFBA089d8BF6b";
const UPDATER_ADDRESS: &str = "0x13A586dDB307E183aB167D4fB4a67536F8891D2f";
const GAS_LIMIT: u64 = 200_000;
const MAX_PRIORITY_FEE_PER_GAS: u64 = 1_000_000_000;
const MAX_FEE_PER_GAS: u64 = 5_000_000_000;
const FAILURE_RETRY_SECONDS: u64 = 15 * 60;
const RECEIPT_ATTEMPTS: usize = 12;
const RECEIPT_POLL_SECONDS: u64 = 5;
type DynError = Box<dyn std::error::Error + Send + Sync>;

/// On-chain values shown by the status API and demo page.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractStatus {
    /// Latest ETH/USD price, scaled to 18 decimals.
    pub latest_price_usd_e18: String,
    /// Human-readable ETH/USD price.
    pub latest_price_usd: String,
    /// Timestamp signed by CoinGecko.
    pub source_timestamp: u64,
    /// Timestamp at which Ethereum recorded the update.
    pub recorded_at: u64,
    /// Hash of the most recently accepted signed payload.
    pub latest_payload_hash: String,
    /// Hash of the most recently accepted signature.
    pub latest_signature_hash: String,
}

enum CycleOutcome {
    Submitted(String),
    NotDue,
}

/// Run updates forever, retrying failures without terminating the HTTP server.
pub async fn run_forever(state: AppState, interval: Duration) {
    // A brief delay lets ingress become healthy before the first outbound cycle.
    tokio::time::sleep(Duration::from_secs(5)).await;

    loop {
        let attempt_at = unix_timestamp().unwrap_or_default();
        {
            let mut status = state.oracle_status.write().await;
            status.last_attempt_at = Some(attempt_at);
            status.phase = "updating".to_owned();
        }

        let delay = match run_once(&state, interval).await {
            Ok(CycleOutcome::Submitted(transaction_hash)) => {
                tracing::info!(%transaction_hash, "oracle update confirmed on Sepolia");
                let mut status = state.oracle_status.write().await;
                status.last_success_at = Some(unix_timestamp().unwrap_or(attempt_at));
                status.last_transaction_hash = Some(transaction_hash);
                status.last_error = None;
                status.phase = "waiting".to_owned();
                interval
            }
            Ok(CycleOutcome::NotDue) => {
                tracing::info!("oracle update is not due yet");
                let mut status = state.oracle_status.write().await;
                status.last_success_at = Some(unix_timestamp().unwrap_or(attempt_at));
                status.last_error = None;
                status.phase = "waiting".to_owned();
                interval.min(Duration::from_secs(60 * 60))
            }
            Err(error) => {
                tracing::error!("oracle update failed: {error}");
                let mut status = state.oracle_status.write().await;
                status.last_error = Some(error.to_string());
                status.phase = "retrying".to_owned();
                Duration::from_secs(FAILURE_RETRY_SECONDS)
            }
        };

        tokio::time::sleep(delay).await;
    }
}

async fn run_once(state: &AppState, interval: Duration) -> Result<CycleOutcome, DynError> {
    let contract = fetch_contract_status(state).await?;
    let now = unix_timestamp()?;
    if contract.recorded_at != 0 && now.saturating_sub(contract.recorded_at) < interval.as_secs() {
        return Ok(CycleOutcome::NotDue);
    }

    let observation = fetch_verified_observation(state).await?;
    if observation.source_timestamp <= contract.source_timestamp {
        return Ok(CycleOutcome::NotDue);
    }

    let nonce = rpc_quantity(
        state,
        "eth_getTransactionCount",
        json!([UPDATER_ADDRESS, "pending"]),
    )
    .await?;
    let calldata = encode_update_price_call(
        &observation.template_id,
        observation.source_timestamp,
        &observation.encoded_value,
        &observation.signature,
    )?;
    let unsigned_transaction = encode_unsigned_eip1559(nonce, &calldata)?;

    let signed = state
        .turnkey_client
        .sign_transaction(
            ORGANIZATION_ID.to_owned(),
            state.turnkey_client.current_timestamp(),
            SignTransactionIntentV2 {
                sign_with: UPDATER_ADDRESS.to_owned(),
                unsigned_transaction,
                r#type: TransactionType::Ethereum,
            },
        )
        .await?;
    let raw = with_hex_prefix(&signed.result.signed_transaction);
    let transaction_hash = rpc_string(state, "eth_sendRawTransaction", json!([raw])).await?;
    {
        let mut status = state.oracle_status.write().await;
        status.last_transaction_hash = Some(transaction_hash.clone());
        status.phase = "confirming".to_owned();
    }
    wait_for_receipt(state, &transaction_hash).await?;
    Ok(CycleOutcome::Submitted(transaction_hash))
}

/// Fetch the current canonical oracle values from Sepolia.
pub async fn fetch_contract_status(state: &AppState) -> Result<ContractStatus, DynError> {
    let (price, source_timestamp, recorded_at, payload_hash, signature_hash) = tokio::try_join!(
        eth_call_word(state, "latestPriceUsdE18()"),
        eth_call_word(state, "sourceTimestamp()"),
        eth_call_word(state, "recordedAt()"),
        eth_call_word(state, "latestPayloadHash()"),
        eth_call_word(state, "latestSignatureHash()"),
    )?;
    let price = word_to_u128(&price)?;

    Ok(ContractStatus {
        latest_price_usd_e18: price.to_string(),
        latest_price_usd: format_e18(price),
        source_timestamp: word_to_u64(&source_timestamp)?,
        recorded_at: word_to_u64(&recorded_at)?,
        latest_payload_hash: format!("0x{}", qos_hex::encode(&payload_hash)),
        latest_signature_hash: format!("0x{}", qos_hex::encode(&signature_hash)),
    })
}

async fn eth_call_word(state: &AppState, function: &str) -> Result<[u8; 32], DynError> {
    let selector = &Keccak256::digest(function.as_bytes())[..4];
    let result = rpc_string(
        state,
        "eth_call",
        json!([{"to": ORACLE_ADDRESS, "data": with_hex_prefix(&qos_hex::encode(selector))}, "latest"]),
    )
    .await?;
    Ok(decode_fixed::<32>(&result, "eth_call result")?)
}

async fn wait_for_receipt(state: &AppState, transaction_hash: &str) -> Result<(), DynError> {
    for _ in 0..RECEIPT_ATTEMPTS {
        let receipt = rpc(
            state,
            "eth_getTransactionReceipt",
            json!([transaction_hash]),
        )
        .await?;
        if receipt.is_null() {
            tokio::time::sleep(Duration::from_secs(RECEIPT_POLL_SECONDS)).await;
            continue;
        }
        let status = receipt
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_data("transaction receipt is missing status"))?;
        return match status {
            "0x1" => Ok(()),
            "0x0" => Err(invalid_data("oracle transaction reverted").into()),
            other => Err(invalid_data(format!("unexpected receipt status {other}")).into()),
        };
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("transaction {transaction_hash} was not confirmed within one minute"),
    )
    .into())
}

async fn rpc_quantity(state: &AppState, method: &str, params: Value) -> Result<u64, DynError> {
    let value = rpc_string(state, method, params).await?;
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(&value), 16)
        .map_err(|error| invalid_data(format!("invalid RPC quantity: {error}")).into())
}

async fn rpc_string(state: &AppState, method: &str, params: Value) -> Result<String, DynError> {
    rpc(state, method, params)
        .await?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid_data(format!("{method} returned a non-string result")).into())
}

async fn rpc(state: &AppState, method: &str, params: Value) -> Result<Value, DynError> {
    let response = state
        .http_client
        .post(SEPOLIA_RPC_URL)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(io::Error::other(format!("Sepolia RPC returned HTTP {status}")).into());
    }
    let body: RpcResponse = response.json().await?;
    if let Some(error) = body.error {
        return Err(io::Error::other(format!(
            "Sepolia RPC {method} failed ({}): {}",
            error.code, error.message
        ))
        .into());
    }
    Ok(body.result)
}

#[derive(Deserialize)]
struct RpcResponse {
    // JSON-RPC uses an explicit null result while a transaction receipt is pending.
    // Preserve that null so wait_for_receipt can poll instead of treating it as an
    // omitted field. Error responses omit result and are handled through `error`.
    #[serde(default)]
    result: Value,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

fn encode_update_price_call(
    template_id: &str,
    timestamp: u64,
    encoded_value: &str,
    signature: &str,
) -> Result<Vec<u8>, io::Error> {
    let template_id = decode_fixed::<32>(template_id, "template ID").map_err(invalid_data)?;
    let encoded_value = decode_hex(encoded_value, "encoded value")?;
    let signature = decode_hex(signature, "signature")?;

    let mut output = Keccak256::digest(b"updatePrice(bytes32,uint256,bytes,bytes)")[..4].to_vec();
    output.extend_from_slice(&template_id);
    output.extend_from_slice(&word_from_u64(timestamp));
    output.extend_from_slice(&word_from_u64(128));
    let signature_offset = 128_u64
        .checked_add(dynamic_abi_len(encoded_value.len())?)
        .ok_or_else(|| invalid_data("ABI offset overflow"))?;
    output.extend_from_slice(&word_from_u64(signature_offset));
    encode_dynamic_abi(&mut output, &encoded_value)?;
    encode_dynamic_abi(&mut output, &signature)?;
    Ok(output)
}

fn encode_unsigned_eip1559(nonce: u64, calldata: &[u8]) -> Result<String, io::Error> {
    let destination = decode_fixed::<20>(ORACLE_ADDRESS, "oracle address").map_err(invalid_data)?;
    let fields = [
        rlp_u64(SEPOLIA_CHAIN_ID),
        rlp_u64(nonce),
        rlp_u64(MAX_PRIORITY_FEE_PER_GAS),
        rlp_u64(MAX_FEE_PER_GAS),
        rlp_u64(GAS_LIMIT),
        rlp_bytes(&destination),
        rlp_u64(0),
        rlp_bytes(calldata),
        rlp_list(&[]),
    ];
    let payload: Vec<u8> = fields.into_iter().flatten().collect();
    let mut encoded = vec![0x02];
    encoded.extend_from_slice(&rlp_list(&payload));
    Ok(qos_hex::encode(&encoded))
}

fn rlp_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    rlp_bytes(&bytes[first..])
}

fn rlp_bytes(value: &[u8]) -> Vec<u8> {
    if value.len() == 1 && value[0] < 0x80 {
        return value.to_vec();
    }
    let mut encoded = rlp_length_prefix(value.len(), 0x80, 0xb7);
    encoded.extend_from_slice(value);
    encoded
}

fn rlp_list(value: &[u8]) -> Vec<u8> {
    let mut encoded = rlp_length_prefix(value.len(), 0xc0, 0xf7);
    encoded.extend_from_slice(value);
    encoded
}

fn rlp_length_prefix(length: usize, short_base: u8, long_base: u8) -> Vec<u8> {
    if length <= 55 {
        return vec![short_base + u8::try_from(length).unwrap_or(55)];
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let length_bytes = &bytes[first..];
    let mut prefix = vec![long_base + u8::try_from(length_bytes.len()).unwrap_or(8)];
    prefix.extend_from_slice(length_bytes);
    prefix
}

fn dynamic_abi_len(length: usize) -> Result<u64, io::Error> {
    let padded = length
        .checked_add(31)
        .ok_or_else(|| invalid_data("ABI value is too large"))?
        / 32
        * 32;
    u64::try_from(32 + padded).map_err(|_| invalid_data("ABI value is too large"))
}

fn encode_dynamic_abi(output: &mut Vec<u8>, value: &[u8]) -> Result<(), io::Error> {
    output.extend_from_slice(&word_from_u64(
        u64::try_from(value.len()).map_err(|_| invalid_data("ABI value is too large"))?,
    ));
    output.extend_from_slice(value);
    let padding = (32 - value.len() % 32) % 32;
    output.resize(output.len() + padding, 0);
    Ok(())
}

fn word_from_u64(value: u64) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn word_to_u64(word: &[u8; 32]) -> Result<u64, io::Error> {
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(invalid_data("contract uint256 does not fit in u64"));
    }
    let mut value = [0_u8; 8];
    value.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(value))
}

fn word_to_u128(word: &[u8; 32]) -> Result<u128, io::Error> {
    if word[..16].iter().any(|byte| *byte != 0) {
        return Err(invalid_data("contract uint256 does not fit in u128"));
    }
    let mut value = [0_u8; 16];
    value.copy_from_slice(&word[16..]);
    Ok(u128::from_be_bytes(value))
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

fn decode_hex(value: &str, name: &str) -> Result<Vec<u8>, io::Error> {
    qos_hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| invalid_data(format!("invalid {name}: {error:?}")))
}

fn with_hex_prefix(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_owned()
    } else {
        format!("0x{value}")
    }
}

fn unix_timestamp() -> Result<u64, io::Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| io::Error::other(format!("system clock error: {error}")))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_policy_compatible_transaction() -> Result<(), io::Error> {
        let calldata = encode_update_price_call(
            "0xdeda2f7938bf877d2f011aa550852d3459794e16944ea0b7513465479752ba93",
            1_788_381_825,
            "0x000000000000000000000000000000000000000000000081a0fb87b871530000",
            "0x6a157125cc065e38c66d6b978f8897d7693282462f041fb68bbdd49cbc5b8322143c59e8ac68aacdb2533a5247e0fb50601a0bbd7f8c1e4a7e5627d685dbb3361c",
        )?;
        let transaction = encode_unsigned_eip1559(0, &calldata)?;
        assert_eq!(transaction, crate::policy_preflight::VALID);
        Ok(())
    }

    #[test]
    fn rlp_matches_known_small_values() {
        assert_eq!(qos_hex::encode(&rlp_u64(0)), "80");
        assert_eq!(qos_hex::encode(&rlp_u64(15)), "0f");
        assert_eq!(qos_hex::encode(&rlp_bytes(b"dog")), "83646f67");
        assert_eq!(qos_hex::encode(&rlp_list(&rlp_bytes(b"dog"))), "c483646f67");
    }

    #[test]
    fn pending_receipt_preserves_null_rpc_result() -> Result<(), serde_json::Error> {
        let response: RpcResponse = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        }))?;

        assert!(response.result.is_null());
        assert!(response.error.is_none());
        Ok(())
    }
}
