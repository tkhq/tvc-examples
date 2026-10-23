# tvc-counterparty-check

A [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com/features/verifiable-cloud/overview) app in TypeScript that enforces a compliance rule over your own data: a payout recipient must be a verified counterparty in your Postgres database.

It looks the recipient up, decides, and returns the verdict signed with the enclave's Ephemeral Key, so anyone holding the response can verify which code produced it and that it ran inside an enclave. The source is TypeScript on Node 24 with one runtime dependency, `pg`. For deployment it is bundled into a single static executable, which is what a TVC pivot has to be.

---

## Contents

- [How it works](#how-it-works)
- [Endpoints](#endpoints)
- [Local development](#local-development)
- [Build the image](#build-the-image)
- [Deploy to TVC](#deploy-to-tvc)
- [Verify a response](#verify-a-response)
- [Configuration](#configuration)
- [Project structure](#project-structure)

---

## How it works

1. When the enclave boots, QOS writes a 32-byte master seed to `/qos.ephemeral.key`. `src/enclave.ts` derives the enclave's P-256 keys from it, following the [QOS key set spec](https://github.com/tkhq/qos/blob/main/src/qos_p256/SPEC.md).
2. `POST /check` looks the recipient up in the `counterparties` table and allows only when `kyb_status = 'verified'`. A database error returns 500, never a verdict.
3. The transaction, the decision and the counterparty row are signed into an **App Proof**. The Boot Proof for the returned `bootEphemeralKey` ties that signing key to the enclave's AWS attestation.

Outside an enclave there is no key file, so `appProof` is `null` and the app otherwise behaves the same.

## Endpoints

```sh
$ curl localhost:3000/health
{"status":"ok"}

$ curl -X POST localhost:3000/check -H 'content-type: application/json' \
    -d '{"to":"0x1111111111111111111111111111111111111111","from":"0xaaaa…","valueWei":"5000000","chainId":8453}'
{
  "allowed": true,
  "reason": "recipient is a verified counterparty",
  "counterparty": {"address":"0x1111…","name":"Acme Logistics Ltd","kybStatus":"verified","verifiedAt":"…"},
  "appProof": {"scheme":"SIGNATURE_SCHEME_EPHEMERAL_KEY_P256","publicKey":"04…","proofPayload":"{…}","signature":"30…"},
  "bootEphemeralKey": "04…"
}
```

Only `to` is required. `from`, `valueWei` and `chainId` are echoed into the signed payload so the verdict is bound to one transaction. The top-level `allowed`, `reason` and `counterparty` fields are unsigned conveniences; consumers should read the verdict from `proofPayload` after verifying the signature.

## Local development

Requires Node 24 and Docker.

```sh
# Postgres with the schema and seed rows
docker run -d --name cpc-pg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=compliance -p 5432:5432 postgres:17-alpine
sleep 3
docker exec -i cpc-pg psql -U postgres -d compliance < db/schema.sql

# A fake seed makes the app sign locally. It proves the code path, not an enclave.
openssl rand -hex 32 > /tmp/fake-ephemeral.key

EPHEMERAL_KEY_FILE=/tmp/fake-ephemeral.key node src/server.ts --port 3000 \
  --database-url postgres://postgres:pw@localhost:5432/compliance \
  --insecure-database
```

In another shell:

```sh
# Verified → allowed, and the signature checks out
curl -s -X POST localhost:3000/check -H 'content-type: application/json' \
  -d '{"to":"0x1111111111111111111111111111111111111111"}' | node scripts/verify.ts

# KYB pending → denied
curl -s -X POST localhost:3000/check -H 'content-type: application/json' \
  -d '{"to":"0x2222222222222222222222222222222222222222"}'
```

Update a row in `counterparties` and the next check reflects it. Stop the database and `/check` returns 500 until it is back.

## Build the image

TVC copies exactly one file out of the image, the pivot at `pivotPath`, and runs it inside the enclave with an empty environment and no container filesystem around it. The pivot therefore has to be a single, fully static executable. The Dockerfile produces one from the TypeScript in two steps: `esbuild` bundles `src/` and `pg` into one JavaScript file, and Node's [single executable application](https://nodejs.org/api/single-executable-applications.html) support injects it into a fully static Node 24 binary from [`pkg-fetch`](https://github.com/yao-pkg/pkg-fetch), pinned by SHA-256. The result is `/tvc_app`, about 70 MB, on a busybox base that exists only to let TVC copy the file out.

```sh
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin

# Build for linux/amd64 (required by Nitro Enclaves) and push.
# The build prints expectedPivotDigest=...; copy it.
docker buildx build --platform linux/amd64 \
  -t ghcr.io/YOUR_GITHUB_USERNAME/tvc-counterparty-check:latest --push .

# Copy the digest of the linux/amd64 manifest, not the index.
docker buildx imagetools inspect ghcr.io/YOUR_GITHUB_USERNAME/tvc-counterparty-check:latest
```

Make the package public in GitHub. The deployment manifest needs:

| Field | Value |
|---|---|
| `pivotContainerImageUrl` | `ghcr.io/YOUR_GITHUB_USERNAME/tvc-counterparty-check:latest@sha256:<linux/amd64 digest>` |
| `pivotPath` | `/tvc_app` |
| `pivotArgs` | `["--port", "3000", "--database-url", "postgres://…"]` |
| `expectedPivotDigest` | the value printed by the build |

`expectedPivotDigest` covers the whole app: runtime, dependencies and your code are all inside `/tvc_app`. The database URL carries a password and belongs in `pivotArgs`, not in the image.


## Deploy to TVC

The database must be reachable from the internet over TLS, and egress must be enabled for your organization and on the app. If your environment only allows outbound HTTPS, a Neon database works with `--database-driver neon-serverless`, which uses port 443. The [quickstart](https://docs.turnkey.com/features/verifiable-cloud/quickstart#cli) covers installing the `tvc` CLI and logging in.

The steps below are manual. The CLI also ships the [`tvc-deployments` agent skill](https://docs.turnkey.com/features/verifiable-cloud/agent-skill), which lets an AI coding agent such as Claude Code, Codex or Cursor run the same lifecycle for you. Install it with `tvc skills save`, then ask the agent to deploy this example with the values from the table above.

### 1. Create the app

```sh
tvc app init --output app.json
# Edit app.json: set "name", "manifestSetParams.name", and "enableEgress": true.
tvc app create --config-file app.json
# Save the returned App ID.
```

### 2. Create and approve the deployment

```sh
tvc deploy init --output deploy.json
# Edit deploy.json with the four values from the table above.
tvc deploy create --config-file deploy.json --app-id <APP_ID>
# Save the returned Deployment ID.
tvc deploy approve --deploy-id <DEPLOY_ID>
```

### 3. Wait for it to go live

```sh
tvc deploy get-status --deploy-id <DEPLOY_ID>
# Live when isTargeted is true and replicas.ready equals replicas.desired.
tvc app list
# publicDomain is the app's hostname.
```

## Verify a response

```sh
curl -s -X POST https://<publicDomain>/check -H 'content-type: application/json' \
  -d '{"to":"0x1111111111111111111111111111111111111111"}' | node scripts/verify.ts
```

`verify.ts` checks the App Proof signature and prints the ephemeral public key. To tie it to the enclave, fetch the Boot Proof for the printed `bootEphemeralKey` and confirm its `ephemeralPublicKeyHex` matches. The [verification flow](https://docs.turnkey.com/features/verifiable-cloud/proofs-and-verification#verification-flow) describes the attestation checks. To block signing on a denied verdict, run the app as a policy sidecar as described in [custom policy enforcement](https://docs.turnkey.com/solutions/verifiable-cloud/custom-policy-enforcement).

## Configuration

| Flag | Default | Purpose |
|---|---|---|
| `--port` | `3000` | Listen port |
| `--database-url` | `$DATABASE_URL` | Postgres connection string |
| `--database-driver` | `pg` | `pg` speaks the Postgres protocol on the URL's port. `neon-serverless` carries it over a WebSocket on port 443, for Neon databases when only HTTPS egress is available |
| `--database-ca-file` | none | Trust only this CA for the database connection |
| `--insecure-database` | off | Plain TCP, for a local database without TLS |
| `EPHEMERAL_KEY_FILE` (env) | `/qos.ephemeral.key` | Override the seed location for local testing |

By default the database connection uses TLS and verifies the server certificate against the root store built into Node.

## Project structure

```
src/
  server.ts       # HTTP server: /health and POST /check
  db.ts           # Postgres pool and the counterparty lookup
  enclave.ts      # Ephemeral key loading, key derivation, App Proof signing
scripts/
  verify.ts       # Offline App Proof verification
db/
  schema.sql      # counterparties table and seed rows
Dockerfile        # esbuild bundle + Node SEA on static Node 24 -> /tvc_app on busybox
sea-config.json   # Node single-executable configuration used by the Dockerfile
```
