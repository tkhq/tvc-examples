# Run and deploy

Two paths: run the whole flow on your machine, or deploy the broker to TVC. Read [ARCHITECTURE.md](ARCHITECTURE.md) first if you want the background.

You need a Turnkey organization where your user may mint (a root user of a one-user quorum works), a throwaway GitHub App installed on one test repository with **Contents: Read-only**, the Rust toolchain, and bun 1.4 or later. Do not use a production App. In the App's settings, leave the webhook off and leave the callback and setup URLs empty.

## Run the demo locally

The broker runs on your machine with an API key file and a random export target. This is for trying it out only.

```sh
bun install
export TURNKEY_ORGANIZATION_ID=<org id> TURNKEY_API_KEY_FILE=<admin API key file>
export TURNKEY_SIGNER_PUBLIC_KEY=<enclaveQuorumPublic, hex>  # printed by: bun admin/src/cli.ts probe

bun admin/src/cli.ts create-broker-user --out .demo/broker-api-key.json
bun admin/src/cli.ts create-export-policy --broker-user-id <user id from above>
bun admin/src/cli.ts import-app-key --pem <app key>.pem --app-client-id <Iv23li...>
```

`import-app-key` prints a secret ID and a fingerprint. Compare the fingerprint with the one GitHub shows for the key. Then run the demo with the secret ID, the `MINT_JWT` signing key you trust as a JWK Set file, and your GitHub details:

```sh
SECRET_ID=<secret id> BROKER_API_KEY_FILE=.demo/broker-api-key.json \
MINTER_API_KEY_FILE=<API key file of the minting user> MINT_JWT_JWKS=<jwks.json> \
GITHUB_APP_CLIENT_ID=<Iv23li...> GITHUB_INSTALLATION_ID=<id> \
GITHUB_OWNER=<login> GITHUB_REPO=<lowercase repo> \
bun run demo
```

The demo mints a JWT, calls the broker, decrypts the token, reads the repository with it, shows a wider scope and an altered request failing, and revokes the token.

## Deploy to TVC

You need the [`tvc` CLI](https://docs.turnkey.com/features/verifiable-cloud/quickstart) (0.17 or later), signed in with `tvc login`, and TVC (with egress) enabled for your organization. The steps below use the files in [`deploy/`](deploy).

Several commands (`approve` and `provision`) review attestation details and need a real terminal. They fail in a shell with no TTY.

**1. Build the image.** It uses [StageX](https://stagex.tools) and needs Docker 26 or later with the containerd image store.

```sh
make out/github-broker/index.json
```

The build prints the `SHA256` of `/tvc_app`. That is `expectedPivotDigest` below. Push the image to a registry TVC can pull from, and use its digest in `pivotContainerImageUrl`.

**2. Create the operators and the quorum key.** The API key must stay the same across deployments, so the app needs its own quorum key (the default one is public). A quorum key needs at least two hosted operators. Give each operator a unique wallet name:

```sh
tvc operator create --kind hosted --name broker-1 --wallet-name broker-wallet-1
tvc operator create --kind hosted --name broker-2 --wallet-name broker-wallet-2
tvc keys create-quorum-key --threshold 2 --operator-ids <id 1>,<id 2>
```

**3. Create the app.** Copy [`deploy/app.json.example`](deploy/app.json.example) and fill in the quorum public key, your operator public key for approving manifests, and the two hosted operator IDs as the share set.

```sh
tvc app create -c app.json
```

**4. Bootstrap.** The API key comes from the quorum key, so it is known only once an enclave runs. Deploy with `--bootstrap`, which serves only `/health` and `/v1/api-public-key`. Copy [`deploy/deploy.json.example`](deploy/deploy.json.example), fill it in, and run:

```sh
tvc deploy create -c deploy.json
tvc deploy approve -d <deploy id> --manifest-id <manifest id> --operator-id <your operator id>
tvc deploy provision -d <deploy id> --operator-id <hosted operator 1 id>
tvc deploy provision -d <deploy id> --operator-id <hosted operator 2 id>
```

`provision` works once the enclave has started. If it says the attestation document is missing, wait a minute and retry. Then read the key from the app's public domain (`app-<app id>.app.turnkey.cloud`):

```sh
curl https://app-<app id>.app.turnkey.cloud/v1/api-public-key
```

**5. Register the broker.**

```sh
bun admin/src/cli.ts create-broker-user --public-key <hex>
bun admin/src/cli.ts create-export-policy --broker-user-id <user id>
bun admin/src/cli.ts import-app-key --pem <app key>.pem --app-client-id <Iv23li...>
```

**6. Deploy with the config.** Fill in [`deploy/broker-config.example.json`](deploy/broker-config.example.json). Set `audience` to the app's public origin and put the `MINT_JWT` key set inline as `trusted_jwks`. Then pass the config to the broker as a pivot argument, in place of `--bootstrap`:

```sh
jq '.pivotArgs = ["--host", "0.0.0.0", "--port", "3000", "--config-json", (input | tostring)]' \
  deploy.json broker-config.json > deploy.live.json
tvc deploy create -c deploy.live.json
```

Approve and provision this deployment the same way, then make it live:

```sh
tvc app set-live-deploy --deploy-id <deploy id>
curl https://app-<app id>.app.turnkey.cloud/v1/info
```

`/v1/info` shows the App key fingerprint, which confirms the enclave exported and decrypted the key. Clients now call the app's public domain with a JWT whose audience is that same origin.
