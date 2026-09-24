//! Route handlers for the TVC signed ETH/USD oracle server.

mod basic;
mod dashboard;
mod keys;
mod oracle;

pub(crate) use basic::health;
pub(crate) use dashboard::{dashboard, oracle_status};
pub(crate) use keys::random_app_proof;
pub(crate) use oracle::{decode_fixed, fetch_verified_observation, signed_eth_usd_observation};
