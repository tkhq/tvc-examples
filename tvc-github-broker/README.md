# tvc-github-broker

A [TVC](https://docs.turnkey.com/features/verifiable-cloud/overview) app that hands out GitHub App installation tokens. An agent or service gets a token narrowed to named repositories and permissions, and never holds the GitHub App private key.

## What it shows

- **A key that never leaves the enclave.** The GitHub App key lives in Turnkey Secrets. The app exports it at startup with a Turnkey API key derived inside the enclave, and the export is encrypted to a key only that enclave holds.
- **A token bound to one request.** Callers present a JWT from Turnkey's `MINT_JWT` activity (the http-authz/v1 profile). The JWT covers one exact HTTP request: method, path, query, chosen headers, and body. Change any of them and the broker refuses.
- **Policy plus an allowlist.** Turnkey policy decides who may mint a JWT. The broker's allowlist decides which repositories and permission levels it will grant.
- **A token only the caller can read.** The broker seals the GitHub token to the HPKE key the caller put in the request body.

## Where to go next

- [DEPLOY.md](DEPLOY.md): run the demo on your machine, then deploy to TVC.
- [ARCHITECTURE.md](ARCHITECTURE.md): how it works, the configuration, and the security notes.
- [SANDBOX.md](SANDBOX.md): run a coding agent in a Docker sandbox with a narrowed GitHub token.

The app verifies JWTs with the [`turnkey_jwt_profiles`](https://github.com/tkhq/rust-sdk/tree/main/jwt_profiles) crate. Until that crate is on crates.io, the build pins a commit of the Turnkey Rust SDK.
