//! GitHub App installation-token broker for Turnkey Verifiable Cloud (TVC).
//!
//! The broker holds a GitHub App private key and mints GitHub installation
//! tokens narrowed to the repositories and permissions named in the request.
//! Each request must carry an http-authz/v1 JWT that
//! binds the exact HTTP request: method, path, query, the `accept` and
//! `x-github-api-version` headers, and the body. Turnkey issues that JWT
//! only after organization policy approves the request.
//!
//! At startup the broker exports the App key from Turnkey Secret Storage
//! (`EXPORT_SECRETS`) to an HPKE key that it generates in memory, decrypts it
//! in process, and never writes it to disk.
//!
//! Module map:
//!
//! - `turnkey_jwt_profiles` (Turnkey Rust SDK crate): the strict http-authz/v1 verifier and its
//!   Axum layer: JOSE header, claims, parent organization, request binding
//!   (path, query, headers, body), and pinned keys.
//! - `tvc_secrets` (workspace crate): Turnkey API stamping and the
//!   `EXPORT_SECRETS` call, Signer verification, and bundle decryption.
//! - [`scope`]: repository and permission parsing, bounds, and the app-side
//!   allowlist.
//! - `query`: the canonical query form the token route requires.
//! - [`appkey`]: PKCS#1 PEM parsing into a `ring` RSA key.
//! - [`github`]: RS256 App JWT signing, the token request, the grant checks,
//!   and revocation.
//! - [`delivery`]: HPKE encryption of the installation token to the caller.
//! - [`router`]: the HTTP surface.

pub mod appkey;
pub mod b64;
pub mod cli;
pub mod config;
pub mod delivery;
pub mod github;
mod query;
pub mod router;
pub mod scope;

pub use turnkey_jwt_profiles::http_authz::unix_now;
