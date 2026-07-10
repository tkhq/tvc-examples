# TVC Sanctions Screener

Verifiable on-chain sanctions screening powered by [Turnkey Verifiable Cloud](https://docs.turnkey.com/getting-started/verifiable-cloud-quickstart) and [Chainalysis](https://www.chainalysis.com/). Users authenticate with a passkey, submit any crypto address for OFAC screening, and receive a result alongside a cryptographic **app proof** and **boot proof** — evidence that the check ran inside a real AWS Nitro Enclave running the exact binary you deployed, signed by a key that never left the enclave.

**Live demo:** https://tvc-chainalysis.up.railway.app/

---

## Table of contents

- [What you'll build](#what-youll-build)
- [Project structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Step 1 — Clone and configure environment](#step-1--clone-and-configure-environment)
- [Step 2 — Set up the Turnkey Auth Proxy](#step-2--set-up-the-turnkey-auth-proxy)
- [Step 3 — Install and run the Next.js app locally](#step-3--install-and-run-the-nextjs-app-locally-no-tvc-yet)
- [Step 4 — Build and test the Go TVC app locally](#step-4--build-and-test-the-go-tvc-app-locally)
- [Step 5 — Build and push the Docker image to GHCR](#step-5--build-and-push-the-docker-image-to-ghcr)
- [Step 6 — Create the TVC app](#step-6--create-the-tvc-app)
- [Step 7 — Create and approve the TVC deployment](#step-7--create-and-approve-the-tvc-deployment)
- [Step 8 — Wire up the deployed TVC app](#step-8--wire-up-the-deployed-tvc-app)
- [Step 9 — Deploy the Next.js app (Vercel)](#step-9--deploy-the-nextjs-app-vercel)
- [How the proofs work](#how-the-proofs-work)
- [Reproducible builds](#reproducible-builds)
- [Database schema](#database-schema)
- [Useful commands](#useful-commands)

---

## What you'll build

A full-stack sanctions screening tool where:

1. Users log in with a **passkey** via the Turnkey UI modal (no passwords, no email codes)
2. Users submit a destination address and ETH amount for OFAC sanctions screening before sending
3. The check runs inside an **AWS Nitro Enclave** via **Turnkey Verifiable Cloud (TVC)**
4. Every result is returned with:
   - An **app proof** — a P-256 signature by the enclave's ephemeral key over the screening result, verifiable in-browser
   - A **boot proof** — a cryptographic attestation from Turnkey confirming the enclave identity and the exact binary that ran
5. Every check is persisted to a **SQLite audit log** alongside both proofs

```
User (browser)
  │  passkey auth via Turnkey UI modal
  ▼
Next.js frontend (auth + UI)
  │  POST /api/screen
  ▼
Next.js API route
  │  POST /screen              │  get_boot_proof (by ephemeral key)
  ▼                            ▼
TVC Go App             Turnkey API
(Nitro Enclave)        (boot proof)
  │
  ▼
Chainalysis Sanctions API
```

---

## Project structure

```
tvc-chainalysis/
├── apps/
│   ├── tvc-app/          # Go pivot binary — runs inside the enclave
│   │   ├── main.go           # HTTP server: GET /health, POST /screen
│   │   ├── chainalysis.go    # Chainalysis Sanctions API client
│   │   ├── proof.go          # Ephemeral key loading, app proof signing, boot key derivation
│   │   ├── go.mod
│   │   └── Dockerfile
│   └── web/              # Next.js — frontend + API routes
│       ├── app/
│       │   ├── page.tsx              # Main page: login prompt or screening tool
│       │   ├── providers.tsx         # TurnkeyProvider wrapper
│       │   └── api/
│       │       └── screen/           # POST: screen address, GET: history
│       ├── components/
│       │   ├── Header.tsx
│       │   ├── LoginButton.tsx
│       │   ├── SendETH.tsx
│       │   ├── ScreeningHistory.tsx
│       │   ├── ScreenedTransaction.tsx
│       │   └── ProofBadge.tsx
│       ├── db/
│       │   ├── schema.ts             # Drizzle schema (users, transactions, screenings)
│       │   └── index.ts              # SQLite connection
│       └── lib/
│           ├── turnkey.ts            # Turnkey server client singleton
│           └── tvc.ts                # TVC HTTP client
```

---

## Prerequisites

- **Go 1.26+** — `brew install go`
- **Node.js 18+** — `brew install node`
- **pnpm** — `npm install -g pnpm`
- **Rust** — `curl https://sh.rustup.rs -sSf | sh` (needed for the `tvc` CLI)
- **`tvc` CLI** — `cargo install tvc`
- **Docker** — for building and pushing the TVC container image
- **GitHub account** — for GHCR (free public image hosting)
- **Turnkey account** — `https://app.turnkey.com`
- **Chainalysis API key** — free from `https://www.chainalysis.com/`

> **NOTE:** Check out [Turnkey Verifiable Cloud Quickstart docs!](https://docs.turnkey.com/getting-started/verifiable-cloud-quickstart)

---

## Step 1 — Clone and configure environment

```bash
git clone https://github.com/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis.git
cd tvc-chainalysis
```

Copy the example env file and fill in your values:

```bash
cp .env.example apps/web/.env.local
```

Open `apps/web/.env.local` and fill in:

| Variable | Where to find it |
|---|---|
| `CHAINALYSIS_API_KEY` | Email from Chainalysis sign-up |
| `TURNKEY_API_PUBLIC_KEY` | Turnkey dashboard → API Keys → New Key |
| `TURNKEY_API_PRIVATE_KEY` | Same (shown once on creation) |
| `TURNKEY_ORG_ID` | Turnkey dashboard → Settings → Organization |
| `NEXT_PUBLIC_TURNKEY_ORG_ID` | Same as above |
| `NEXT_PUBLIC_AUTH_PROXY_CONFIG_ID` | See Step 2 below |

Leave `TVC_APP_URL` and `TVC_APP_ID` empty for now — you'll fill those in after deploying the TVC app.

---

## Step 2 — Set up the Turnkey Auth Proxy

The Auth Proxy lets the frontend call Turnkey without exposing your parent org's API key in the browser. The `handleLogin()` modal is powered by it.

1. Go to **https://app.turnkey.com/dashboard/auth**
2. Click **Auth Proxy** tab → toggle it **ON**
3. Under **Allowed Origins**, add:
   - `http://localhost:3000` (local dev)
   - Your production URL (e.g. `https://your-app.vercel.app`)
4. Under **Authentication Methods**, enable **Passkey** (disable email OTP if you want passkey-only)
5. Copy the **Auth Proxy Config ID** → paste into `NEXT_PUBLIC_AUTH_PROXY_CONFIG_ID`

---

## Step 3 — Install and run the Next.js app locally (no TVC yet)

```bash
cd apps/web
pnpm install
pnpm db:push   # creates local.db with the users, transactions, and screenings tables
pnpm dev
```

Visit `http://localhost:3000`. You'll see the login prompt with a **Log in / Sign up** button that opens the Turnkey passkey modal. After authenticating you'll reach the screening tool, but address screening won't work yet (`TVC_APP_URL` is not set).

### How the auth flow works

1. User clicks **Log in / Sign up** → Turnkey modal opens
2. First visit: browser prompts to **create a passkey** (biometric/device PIN)
3. Returning visit: browser prompts to **use existing passkey**
4. On success `authState` becomes `Authenticated` and the screening tool appears
5. Sign-out calls `logout()` from `useTurnkey()` — no server-side session involved

Authentication is entirely client-side via `@turnkey/react-wallet-kit`. No cookies, no JWTs, no custom session management.

---

## Step 4 — Build and test the Go TVC app locally

The Go app is a plain HTTP server that calls the Chainalysis API. Test it before wrapping it in Docker.

```bash
cd apps/tvc-app
go build -o tvc_app .

# Run locally
CHAINALYSIS_API_KEY=your-key ./tvc_app --port 3000

# Health check
curl http://localhost:3000/health
# → {"status":"ok"}

# Screen a known sanctioned address (real Chainalysis call — see note on egress below)
curl -X POST http://localhost:3000/screen \
  -H "Content-Type: application/json" \
  -d '{"address":"0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a"}'
# → {"address":"0x1da5...","sanctioned":true,"identifications":[...],"appProof":null,"bootEphemeralKey":""}
# (appProof and bootEphemeralKey are null/empty outside an enclave — no ephemeral key file)
```

### Note on egress

`CheckAddress` calls the Chainalysis Sanctions API for every address. Inside the enclave this requires TVC external connectivity (`externalConnectivity: true`) to be enabled so the app can reach `public.chainalysis.com`.

This address is useful for testing a known result against the live API:

| Address | Result |
|---|---|
| `0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a` | Sanctioned (OFAC SDN — Secondeye Solution) |

---

## Step 5 — Build and push the Docker image to GHCR

```bash
cd apps/tvc-app

# Create a GitHub Personal Access Token with the `write:packages` scope:
# https://github.com/settings/tokens/new?scopes=write:packages
#
# Set it without it appearing in shell history.
# `-s` silences terminal echo so the token isn't visible as you type.
# Because `read` is a shell builtin, the token value never appears as a
# command argument
read -s GITHUB_TOKEN && export GITHUB_TOKEN

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin

# Build for linux/amd64 (required by Nitro Enclaves)
docker buildx build \
  --platform linux/amd64 \
  -t ghcr.io/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis:latest \
  --push \
  .
```

Make the package public in GitHub → Packages → your image → Package settings → Change visibility → Public.

### Get the image digest (for Container Image URL)

TVC requires the single-platform `linux/amd64` digest, not the multi-platform index digest. Use `imagetools inspect` to get the correct one:

```bash
docker buildx imagetools inspect ghcr.io/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis:latest
```

Look for the manifest with `Platform: linux/amd64` and copy its digest. The URL to use in the deployment manifest is:

```
ghcr.io/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis@sha256:<amd64-digest>
```

### Get the pivot binary digest

The TVC deployment also requires the SHA256 of the binary _inside_ the container:

```bash
docker create --name tmp-extract \
  ghcr.io/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis:latest /bin/true \
  && docker cp tmp-extract:/tvc_app ./tvc_app_extracted \
  && docker rm tmp-extract

sha256sum ./tvc_app_extracted
# Copy this hash — you'll need it in Step 7
```

---

## Step 6 — Create the TVC app

You need TVC access enabled for your org. Contact Turnkey if you haven't already.

### Option A — Dashboard

1. Go to **https://app.turnkey.com/dashboard/tvc** → **Create app**
2. Name: `tvc-chainalysis`
3. Paste your operator public key (from `tvc login`)
4. Click **Create new TVC App**

### Option B — CLI

```bash
# Login with the TVC CLI (generates an operator keypair)
tvc login

# Generate app template
tvc app init --output app.json

# Edit app.json:
# - Set "name" to "tvc-chainalysis"

# Create the app
tvc app create --config-file app.json
```

---

## Step 7 — Create the TVC deployment

### Option A — Dashboard

1. Click into your app → **Create deployment**
2. Fill in the fields:
   - **Container Image URL**: `ghcr.io/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis:latest@sha256:<image-digest>`
   - **Executable Path**: `/tvc_app`
   - **Executable Args**: `--port 3000 --chainalysis-api-key <your-chainalysis-api-key>`
   - **Public ingress port**: `3000`
   - **Health check port**: `3000`
   - **Health check type**: `HTTP`
   - **Executable digest**: the SHA256 from Step 5 (digest of the binary, not the image)
3. Click **Deploy TVC App**

When the app is deployed you will see it appear as a row in the Deployments table for the app in the Turnkey Dashboard. The `id` column has the deployment ID you will need to copy for step 8.

### Option B — CLI

```bash
tvc deploy init   # generates a deploy template

# Edit the generated file:
# - qosVersion: <fill in the QOS version — check TVC docs or dashboard>
# - pivotContainerImageUrl: ghcr.io/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis:latest@sha256:...
# - pivotPath: /tvc_app
# - pivotArgs: ["--port", "3000", "--chainalysis-api-key", "<your-chainalysis-api-key>"]
# - expectedPivotDigest: <sha256 from Step 5>
# - debugMode: false
# - pivotContainerEncryptedPullSecret: remove this field (image is public)
# - healthCheckType: TVC_HEALTH_CHECK_TYPE_HTTP
# - healthCheckPort: 3000
# - publicIngressPort: 3000

tvc deploy create --config-file deploy-2026-06-11-175029.json   # UPDATE THIS FILENAME TO YOUR GENERATED CONFIG FILE - filename includes a timestamp generated at init time
```

After a successful `deploy create` command you should see a success message and the deployment ID, app ID, and the config file referenced for deployment, similar to the log below:

```bash
Deployment created successfully!

Deployment ID: 6dd...6b2
App ID: 189...716
Config: deploy-2026-06-11-175029.json
```

## Step 8 — Approve the TVC deployment

Whether you deployed from the Turnkey Dashboard or via CLI this step will be done via the `tvc` CLI.

You will already have the deployment ID from the previous step. To get the Operator ID go to the Turnkey Dashboard and navigate to Verifiable Cloud. Find your app and click through to find the Manifest Approvers section, under which you will find and copy the `Operator ID` to use in the command below: 

```bash
tvc deploy approve \
  --deploy-id <DEPLOYMENT_UUID> \
  --operator-id <OPERATOR_UUID>
```

On success you will be presented with the Manifest Approval.

```bash
========================================
         MANIFEST APPROVAL
========================================

NAMESPACE
─────────────────────────────────────
  Name:       prod/tvc/189...716
  Nonce:      1781274433
  Quorum Key: 044...83e

> Approve namespace? Yes
...
```

On the Turnkey Dashboard find and click through to your app in the Verifiable Cloud section and click on your deployment. There you will find the App Container and QOS Manifest. 

Confirm each by comparing to the QOS Manifest until all sections are approved:

```bash
...
========================================
    ALL SECTIONS APPROVED
========================================

{
  "signature": "fb6...148",
  "member": {
    "alias": "operator-1",
    "pubKey": "04c...ad9"
  }
}

Posting approval to Turnkey...

Approval posted successfully!

Approval IDs: ["b8e3...ca8"]
Manifest ID: 3bc...b04
Operator ID: 030...7a3
```

---

## Step 9 — Wire up the deployed TVC app

Once the deployment shows **LIVE** on the dashboard (usually takes 2–5 minutes after approval):

Your app is accessible at:
```
https://app-<YOUR_APP_UUID>.turnkey.cloud
```

Update `apps/web/.env.local`:
```
TVC_APP_URL=https://app-<YOUR_APP_UUID>.turnkey.cloud
TVC_APP_ID=<YOUR_APP_UUID>
```

Test it:
```bash
curl https://app-<YOUR_APP_UUID>.turnkey.cloud/health
# → {"status":"ok"}
```

Restart the Next.js dev server and try screening one of the two demo addresses. The app proof and boot proof should now appear on every result.

---

## Step 10 — Deploy the Next.js app (Vercel)

```bash
cd apps/web
pnpm dlx vercel
```

In the Vercel dashboard, add all the env vars from `.env.local` (the `NEXT_PUBLIC_*` ones must be added as plain env vars, not secrets, for the browser to access them). Add your Vercel URL to the Turnkey Auth Proxy's allowed origins.

---

## How the proofs work

When you screen an address:

1. The Next.js API calls `POST /screen` on the TVC Go app running in the enclave
2. The enclave checks the address via the Chainalysis Sanctions API and **signs the result** with its ephemeral P-256 private key — a key derived from the QOS master seed that never leaves the enclave
3. The response includes:
   - `appProof` — scheme, public key, the signed JSON payload, and the signature
   - `bootEphemeralKey` — the 130-byte QOS KeySet (encrypt pubkey + sign pubkey) derived from the same master seed
4. The Next.js API calls Turnkey's `get_boot_proof` using `bootEphemeralKey` to fetch the boot proof for the exact replica that handled the request
5. Both proofs are stored in the SQLite `screenings` table

### App proof verification (in-browser)

`ProofBadge` uses the Web Crypto API to verify the app proof client-side:

1. Import `appProof.publicKey` (the enclave's P-256 signing key) as an ECDSA verify key
2. Convert `appProof.signature` from ASN.1 DER to raw `r||s` (Web Crypto requires this format)
3. Verify the signature over `appProof.proofPayload` (the raw JSON string) with SHA-256

If valid, the result hasn't been tampered with in transit.

### Boot proof verification

The boot proof links the app proof signing key back to a real enclave:

1. `bootProof.ephemeralPublicKeyHex` ends with `appProof.publicKey` — they share the same QOS master seed
2. `bootProof.awsAttestationDocB64` is a COSE Sign1 document signed by AWS, containing PCR measurements that identify the specific Nitro Enclave and Turnkey's AWS account
3. `bootProof.qosManifestB64` contains the binary hash of the deployed `tvc_app` — compare against the SHA256 from Step 5 to confirm the expected binary ran

---

## Reproducible builds

The `tvc-app` binary is built deterministically so that anyone can verify the published image digest matches the source code.

### Why it matters

A TVC app runs inside a Turnkey enclave. The enclave is bootstrapped from a container image whose digest is committed to the TVC deployment configuration. If the binary changes between builds, even from identical source, the digest won't match and the enclave attestation fails. Pinning every input to the build eliminates that class of drift and ensures builds are reproducible.

### What is pinned

| Input | How it's pinned |
|---|---|
| Go toolchain | `golang:1.26.4-alpine@sha256:7a3e5009...` in `Dockerfile` |
| Runtime base | `stagex/core-busybox:1.36.1@sha256:cac5d773...` in `Dockerfile` |
| Go dependencies | `go.sum` committed in source |

`-trimpath` is also set on the `go build` command to strip local filesystem paths from the binary, ensuring the digest is the same regardless of the build machine.

### Refreshing the toolchain digest

When upgrading Go, update `go.mod` and the `FROM` tag together, then re-pin:

```sh
docker pull golang:<new-version>-alpine
docker inspect golang:<new-version>-alpine --format='{{index .RepoDigests 0}}'
```

Replace the `@sha256:...` in the `Dockerfile` `FROM` line with the new digest.

---

## Database schema

```sql
-- One row per authenticated Turnkey user (sub-org).
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  turnkey_user_id TEXT NOT NULL UNIQUE,
  turnkey_sub_org_id TEXT NOT NULL UNIQUE,
  turnkey_wallet_id TEXT NOT NULL UNIQUE,
  wallet_address TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One row per transaction intent (created before screening, updated after).
CREATE TABLE transactions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  from_address TEXT NOT NULL,
  to_address TEXT NOT NULL,
  value_wei TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '0x',
  chain_id INTEGER NOT NULL,
  tx_hash TEXT,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | submitted | confirmed | blocked
  submitted_at TEXT,
  confirmed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Full audit log of every sanctions screening.
CREATE TABLE screenings (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  transaction_id TEXT NOT NULL REFERENCES transactions(id),
  address TEXT NOT NULL,
  is_sanctioned INTEGER NOT NULL DEFAULT 0,
  identifications TEXT NOT NULL,   -- JSON array
  proof_scheme TEXT,
  proof_public_key TEXT,
  proof_payload TEXT,
  proof_signature TEXT,
  boot_proof TEXT,                 -- JSON object (null if proof fetch failed)
  outcome TEXT NOT NULL,           -- allowed | blocked
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

Run `pnpm db:studio` from `apps/web/` to browse the database in a web UI.

---

## Useful commands

```bash
# Local dev
cd apps/web && pnpm dev

# Rebuild DB schema after changes
cd apps/web && pnpm db:push

# Browse DB
cd apps/web && pnpm db:studio

# Build Go binary locally
cd apps/tvc-app && go build -o tvc_app .

# Rebuild and push Docker image
cd apps/tvc-app && docker buildx build --platform linux/amd64 \
  -t ghcr.io/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis:latest --push .

# Check TVC deployment status
tvc deploy status --app-id <APP_UUID>
```
