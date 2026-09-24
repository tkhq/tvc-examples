//! Shared oracle configuration constants.

/// Production Turnkey API endpoint used unless another environment is selected.
pub(crate) const DEFAULT_TURNKEY_API_BASE_URL: &str = "https://api.turnkey.com";
/// Public Sepolia JSON-RPC endpoint used unless another provider is selected.
pub(crate) const DEFAULT_SEPOLIA_RPC_URL: &str = "https://ethereum-sepolia-rpc.publicnode.com";
/// Ethereum Sepolia chain ID.
pub(crate) const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
/// Deployed signed ETH/USD oracle contract.
pub(crate) const ORACLE_ADDRESS: &str = "0x9890Df3894EbF1dbCD8E69aA7fafFBA089d8BF6b";
/// Turnkey-managed account authorized to update the oracle.
pub(crate) const UPDATER_ADDRESS: &str = "0x13A586dDB307E183aB167D4fB4a67536F8891D2f";
/// CoinGecko Airnode whose signatures this example accepts.
pub(crate) const SOURCE_AIRNODE: &str = "0x9dB03a07bE313B3C08261B1d1606D511f3560D9e";
/// API3 template ID for CoinGecko's signed ETH/USD observation.
pub(crate) const ETH_USD_TEMPLATE_ID: &str =
    "0xdeda2f7938bf877d2f011aa550852d3459794e16944ea0b7513465479752ba93";
