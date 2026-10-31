# tvc-github-broker

A TVC app that brokers GitHub App installation tokens. An agent gets a token narrowed to named repositories and permissions, and never holds the GitHub App private key. Turnkey policy decides who can ask, and the broker's allowlist decides what they can get.

The broker accepts only a request-bound JWT from the http-authz/v1 profile of `ACTIVITY_TYPE_MINT_JWT`. The JWT covers one exact HTTP request. The broker verifies it with the [`turnkey_jwt_profiles`](https://github.com/tkhq/rust-sdk/tree/main/jwt_profiles) crate.

## How it works

1. The GitHub App key is stored in Turnkey Secret Storage. At startup the broker exports it into enclave memory with `EXPORT_SECRETS`, decrypts it in process, and never writes it to disk.
2. A client asks Turnkey for a JWT for `POST /v1/installations/{id}/tokens?permissions=...&repositories=...`, binding the method, path, query, the `accept` and `x-github-api-version` headers, and the body (which carries the client's HPKE public key).
3. The client calls the broker with the JWT. The broker verifies the token, checks that it describes this exact request, and checks the scope against its allowlist.
4. The broker signs a short-lived GitHub App JWT and asks GitHub for a token with exactly the requested scope. If GitHub grants more, the broker revokes the token and fails.
5. The broker seals the token to the client's HPKE key. Only the original caller can read it.

## Run the demo

You need a Turnkey organization where your user may mint (a root user of a one-user quorum works), the Rust toolchain, bun 1.4 or later, and a throwaway GitHub App installed on one test repository with **Contents: Read-only**. Do not use a production App.

```sh
bun install
export TURNKEY_ORGANIZATION_ID=<org id> TURNKEY_API_KEY_FILE=<admin API key file>
export TURNKEY_SIGNER_PUBLIC_KEY=<Signer public key, hex>  # unless it is the SDK's production key

bun admin/src/cli.ts create-broker-user --out .demo/broker-api-key.json
bun admin/src/cli.ts create-export-policy --broker-user-id <user id from above>
bun admin/src/cli.ts import-app-key --pem <app key>.pem --app-client-id <Iv23li...>
```

Then run the demo with the secret ID printed by `import-app-key`, the MINT_JWT signing key you trust as a JWK Set file, and your GitHub details:

```sh
SECRET_ID=<secret id> BROKER_API_KEY_FILE=.demo/broker-api-key.json \
MINTER_API_KEY_FILE=<API key file of the minting user> MINT_JWT_JWKS=<jwks.json> \
GITHUB_APP_CLIENT_ID=<Iv23li...> GITHUB_INSTALLATION_ID=<id> \
GITHUB_OWNER=<login> GITHUB_REPO=<lowercase repo> \
bun run demo
```

The demo mints a JWT, calls the broker, decrypts the token, reads the repository with it, shows a wider scope and an altered request failing, and revokes the token. Compare the fingerprint that `import-app-key` prints with the one GitHub shows.

## Build the image

The image is built with [StageX](https://stagex.tools) and needs Docker 26 or later with the containerd image store.

```sh
make out/github-broker/index.json
```

The build prints the `SHA256` of `/tvc_app`, which TVC needs for the deployment.

## Configuration

The broker reads a JSON config. `scripts/demo.ts` writes a complete one. It sets the audience (the broker's exact origin), `organization_id` (the top-level organization that `iss` must name), `trusted_jwks_path` (the MINT_JWT key set), the GitHub App client ID, the Turnkey secret to export, and `installations`, an allowlist of repositories and permission levels. Each installation can also be limited to some organizations. Set `detailed_auth_errors` to see why a token was rejected. Leave it off in production.

## Tests

`make -C src test` runs the Rust tests, and `bun test tests/` runs the shared digest, header, and query vectors. The end-to-end path needs real Turnkey and GitHub, so `bun run demo` is the check.

## Security notes and limits

- The App key is never logged or written to disk, and is zeroized after use. RSA signing uses `ring`, not the `rsa` crate (RUSTSEC-2023-0071).
- Tokens are not single-use. A replayed JWT yields a new token for the same exact request until `exp`. The new token is sealed to the original caller's key.
- Policy can match the exact query string, but it cannot express a subset of repositories. The broker's allowlist therefore limits the repositories and permissions. Repository names must be lowercase, because GitHub matches names without case.
- The broker reads its Turnkey API key from a file. This is a demo shortcut.
- `EXPORT_SECRETS` is not yet bound to the enclave. Anyone holding the broker user's API key can export the key to a target of their choice.
- The broker serves plain HTTP and connects directly to GitHub and Turnkey. TLS termination and egress routing decide who can see the JWT. HPKE delivery protects the token either way.
- The `turnkey_jwt_profiles` dependency is pinned to a Git commit of the Turnkey Rust SDK until the crate is on crates.io.
