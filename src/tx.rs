//! Minimal unsigned-EVM-transaction parser.
//!
//! Turnkey's `unsignedTransaction` is the raw serialized transaction that gets
//! hashed for signing — i.e. what alloy calls the "encoded for signing" form:
//!   - EIP-1559: `0x02 || rlp([chainId, nonce, maxPrio, maxFee, gas, to, value, data, accessList])`
//!   - EIP-2930: `0x01 || rlp([...])`
//!   - legacy:   `rlp([nonce, gasPrice, gas, to, value, data, chainId, 0, 0])`
//!
//! The rules engine only needs `to`, `value`, and the calldata (for the 4-byte
//! selector + args), so we decode into that and drop the rest.
//!
//! This module is consumed by the rules engine.
#![allow(dead_code)]

use std::fmt;

use alloy_consensus::transaction::RlpEcdsaDecodableTx;
use alloy_consensus::{Transaction, TxEip1559, TxEip2930};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_rlp::{Decodable, Header};

/// The fields of an unsigned transaction that classification cares about.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedTx {
    /// Recipient. `None` for contract-creation transactions.
    pub to: Option<Address>,
    /// Native value transferred, in wei.
    pub value: U256,
    /// Calldata.
    pub input: Bytes,
}

impl ParsedTx {
    /// The 4-byte function selector, if the calldata is long enough.
    pub fn selector(&self) -> Option<[u8; 4]> {
        self.input.get(..4).map(|s| s.try_into().unwrap())
    }
}

/// Why an unsigned transaction could not be parsed.
#[derive(Debug)]
pub enum ParseError {
    /// No bytes to parse.
    Empty,
    /// First byte is not a supported transaction type / RLP list.
    UnsupportedType(u8),
    /// The RLP body was malformed.
    Rlp(alloy_rlp::Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty transaction"),
            ParseError::UnsupportedType(b) => write!(f, "unsupported transaction type byte {b:#04x}"),
            ParseError::Rlp(e) => write!(f, "malformed RLP: {e}"),
        }
    }
}

/// Parse a raw unsigned transaction (already hex-decoded) into [`ParsedTx`].
pub fn parse_unsigned(raw: &[u8]) -> Result<ParsedTx, ParseError> {
    let first = *raw.first().ok_or(ParseError::Empty)?;
    match first {
        // Typed transactions: strip the type byte, decode the RLP payload.
        // Their signing form is symmetric with `rlp_decode`.
        0x02 => decode_typed::<TxEip1559>(&raw[1..]),
        0x01 => decode_typed::<TxEip2930>(&raw[1..]),
        // Legacy: the whole thing is an RLP list (first byte is a list header, >= 0xc0).
        b if b >= 0xc0 => decode_legacy(raw),
        b => Err(ParseError::UnsupportedType(b)),
    }
}

/// Decode a typed tx's RLP body via its [`Transaction`] accessors.
fn decode_typed<T: RlpEcdsaDecodableTx + Transaction>(
    mut buf: &[u8],
) -> Result<ParsedTx, ParseError> {
    let tx = T::rlp_decode(&mut buf).map_err(ParseError::Rlp)?;
    Ok(ParsedTx {
        to: tx.to(),
        value: tx.value(),
        input: tx.input().clone(),
    })
}

/// Decode a legacy tx's *signing payload*. Unlike a stored legacy tx, this is
/// `rlp([nonce, gasPrice, gas, to, value, data, chainId, 0, 0])` (EIP-155), so
/// we read the six fields we need and ignore any EIP-155 trailer.
fn decode_legacy(mut buf: &[u8]) -> Result<ParsedTx, ParseError> {
    let header = Header::decode(&mut buf).map_err(ParseError::Rlp)?;
    if !header.list {
        return Err(ParseError::Rlp(alloy_rlp::Error::UnexpectedString));
    }
    let _nonce = u64::decode(&mut buf).map_err(ParseError::Rlp)?;
    let _gas_price = U256::decode(&mut buf).map_err(ParseError::Rlp)?;
    let _gas_limit = u64::decode(&mut buf).map_err(ParseError::Rlp)?;
    let kind = TxKind::decode(&mut buf).map_err(ParseError::Rlp)?;
    let value = U256::decode(&mut buf).map_err(ParseError::Rlp)?;
    let input = Bytes::decode(&mut buf).map_err(ParseError::Rlp)?;
    let to = match kind {
        TxKind::Call(addr) => Some(addr),
        TxKind::Create => None,
    };
    Ok(ParsedTx { to, value, input })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxLegacy};
    use alloy_primitives::{address, TxKind, U256};

    /// Build `transfer(address,uint256)` calldata.
    fn transfer_calldata(recipient: Address, amount: u64) -> Vec<u8> {
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer selector
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(recipient.as_slice()); // right-padded to 32 bytes
        data.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
        data
    }

    #[test]
    fn round_trip_eip1559_erc20_transfer() {
        let token = address!("1111111111111111111111111111111111111111");
        let recipient = address!("00000000000000000000000000000000000000ff");
        let data = transfer_calldata(recipient, 1000);

        let tx = TxEip1559 {
            chain_id: 1,
            to: TxKind::Call(token),
            value: U256::ZERO,
            input: data.clone().into(),
            ..Default::default()
        };
        let raw = tx.encoded_for_signing();

        let parsed = parse_unsigned(&raw).expect("parses");
        assert_eq!(parsed.to, Some(token));
        assert_eq!(parsed.value, U256::ZERO);
        assert_eq!(parsed.selector(), Some([0xa9, 0x05, 0x9c, 0xbb]));
        assert_eq!(parsed.input.as_ref(), data.as_slice());
    }

    #[test]
    fn round_trip_legacy_native_transfer() {
        let recipient = address!("00000000000000000000000000000000000000aa");
        let tx = TxLegacy {
            chain_id: Some(1),
            to: TxKind::Call(recipient),
            value: U256::from(5_000_000u64),
            input: Bytes::new(),
            ..Default::default()
        };
        let raw = tx.encoded_for_signing();

        let parsed = parse_unsigned(&raw).expect("parses");
        assert_eq!(parsed.to, Some(recipient));
        assert_eq!(parsed.value, U256::from(5_000_000u64));
        assert_eq!(parsed.selector(), None, "no calldata -> no selector");
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(parse_unsigned(&[]), Err(ParseError::Empty)));
    }

    #[test]
    fn rejects_unknown_type_byte() {
        assert!(matches!(
            parse_unsigned(&[0x7f, 0x00]),
            Err(ParseError::UnsupportedType(0x7f))
        ));
    }
}
