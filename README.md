# TVC Sanctions Screener

Verifiable on-chain sanctions screening powered by [Turnkey Verifiable Cloud](https://docs.turnkey.com/getting-started/verifiable-cloud-quickstart) and [Chainalysis](https://www.chainalysis.com/). Users authenticate with a passkey, submit any crypto address for OFAC screening, and receive a result alongside a cryptographic **boot proof** — evidence that the check ran inside a real AWS Nitro Enclave running the exact binary you deployed.

---

## What you'll build

A full-stack sanctions screening tool where:

1. Users log in with a **passkey** via the Turnkey UI modal (no passwords, no email codes)
2. Users submit any crypto address for OFAC sanctions screening
3. The check runs inside an **AWS Nitro Enclave** via **Turnkey Verifiable Cloud (TVC)**
4. Every result is returned with a **boot proof** — a cryptographic attestation that the exact expected binary ran in a real enclave
5. Every check is persisted to a **SQLite audit log** alongside the boot proof

```
User (browser)
  │  passkey auth via Turnkey UI modal
  ▼
Next.js frontend (auth + UI)
  │  POST /api/screen
  ▼
Next.js API route
  │  POST /screen              │  getLatestBootProof
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
│   │   ├── main.go
│   │   ├── chainalysis.go
│   │   ├── go.mod
│   │   └── Dockerfile
│   └── web/              # Next.js 16 — frontend + API routes
│       ├── app/
│       │   ├── page.tsx              # Main page: login prompt or screening tool
│       │   ├── providers.tsx         # TurnkeyProvider wrapper
│       │   └── api/
│       │       └── screen/           # POST: screen address, GET: history
│       ├── components/
│       │   ├── Header.tsx
│       │   ├── ScreeningTool.tsx
│       │   └── ProofBadge.tsx
│       ├── db/
│       │   ├── schema.ts             # Drizzle schema (screenings only)
│       │   └── index.ts              # SQLite connection
│       └── lib/
│           ├── turnkey.ts            # Turnkey server client singleton
│           └── tvc.ts                # TVC HTTP client
```

---

## Prerequisites

- **Go 1.22+** — `brew install go`
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
pnpm db:push   # creates local.db with the screenings table
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

# Screen a known sanctioned address
curl -X POST http://localhost:3000/screen \
  -H "Content-Type: application/json" \
  -d '{"address":"0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a"}'
# → {"address":"0x1da5...","sanctioned":true,"identifications":[...]}
```

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

The TVC deployment requires the full image URL with digest:

```bash
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis:latest
# → ghcr.io/YOUR_GITHUB_ORG_OR_USERNAME/tvc-chainalysis@sha256:<image-digest>
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
tvc app create app.json
```

> **Note on egress:** `externalConnectivity` is not yet supported in TVC, so this demo implements a mock Chainalysis call inside the enclave.

---

## Step 7 — Create and approve the TVC deployment

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
4. Approve the deployment:

```bash
tvc deploy approve \
  --deploy-id <DEPLOYMENT_UUID> \
  --operator-id <OPERATOR_UUID>
```

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

tvc deploy create deploy.json
```

Approve the manifest:

```bash
tvc deploy approve \
  --deploy-id <DEPLOYMENT_UUID> \
  --operator-id <OPERATOR_UUID>
```

---

## Step 8 — Wire up the deployed TVC app

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

Restart the Next.js dev server and try screening an address. The boot proof should now appear on every result.

---

## Step 9 — Deploy the Next.js app (Vercel)

```bash
cd apps/web
pnpm dlx vercel
```

In the Vercel dashboard, add all the env vars from `.env.local` (the `NEXT_PUBLIC_*` ones must be added as plain env vars, not secrets, for the browser to access them). Add your Vercel URL to the Turnkey Auth Proxy's allowed origins.

---

## How the boot proof works

When you screen an address:

1. The Next.js API calls `POST /screen` on the TVC app running in the enclave
2. The enclave calls the Chainalysis API and returns the result
3. The Next.js API separately calls Turnkey's `getLatestBootProof` endpoint
4. Turnkey returns a boot proof containing:
   - `awsAttestationDocB64` — the AWS Nitro attestation document (signed by AWS)
   - `qosManifestB64` — the QOS manifest (includes the binary hash baked into the deployment)
5. Together, these prove: "a real AWS Nitro Enclave was running the exact binary you deployed"
6. The proof is stored in the SQLite `screenings` table alongside the result

Anyone can independently verify the proof by:
1. Decoding `awsAttestationDocB64` — verifies it's a real Nitro Enclave and extracts PCR values
2. Decoding `qosManifestB64` — verifies the PCR values match the QOS version + your binary hash

---

## Database schema

```sql
-- One row per (user, wallet address) pair.
-- org_id + user_id are the Turnkey sub-org and user IDs from the session.
CREATE TABLE user_wallets (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  address TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (org_id, address)
);

-- Full audit log of every screening.
-- user_wallet_id links back to the user wallet that initiated the check.
-- destination_address is denormalized for simple queries without joins.
CREATE TABLE screenings (
  id TEXT PRIMARY KEY,
  user_wallet_id TEXT NOT NULL REFERENCES user_wallets(id),
  destination_address TEXT NOT NULL,
  sanctioned INTEGER NOT NULL,    -- boolean
  identifications TEXT NOT NULL,  -- JSON array
  boot_proof TEXT,                -- JSON object (null if proof fetch failed)
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
