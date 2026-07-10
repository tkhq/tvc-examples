# tvc-cosign

A [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com/features/verifiable-cloud/overview)
pivot binary that runs inside an AWS Nitro Enclave and exposes a single
`POST /cosign` endpoint. It parses an unsigned EVM transaction, classifies it
against a baked-in ruleset, and returns a **stamped** Turnkey `SIGN_TRANSACTION`
activity request signed by one of two keys deterministically derived from the
enclave's quorum key: `programmatic` or `admin`. The customer submits that
request to Turnkey, where policies either auto-complete it (programmatic) or hold
it for human approval (admin).

The app **never holds Turnkey credentials and makes zero network egress**, it
only stamps. All trust flows from the quorum-key-derived API keys plus Turnkey
policies, and every decision is accompanied by a verifiable **App Proof**.

```
unsigned tx bytes ──▶ POST /cosign (this app, in the enclave)
                          │ 1. parse: to / selector / args / value
                          │ 2. classify: PROGRAMMATIC | ADMIN | REJECT
                          │ 3. build SIGN_TRANSACTION_V2 body
                          │ 4. stamp body with the derived prog OR admin key
                          │ 5. App-Proof the decision with the ephemeral key
                          ▼
        { activityBody, xStamp, classification, appProof, bootEphemeralKey }
                          │
              customer submits activityBody + xStamp to api.turnkey.com
                          ▼
        Turnkey policies evaluate the stamping API user:
          • TVC programmatic  → policy ALLOW           → COMPLETED
          • TVC admin         → require human consensus → CONSENSUS_NEEDED
```

---

## Contents

- [How it works](#how-it-works)
- [Endpoints](#endpoints)
- [Local development](#local-development)
- [Reproducible build](#reproducible-build)
- [Deploy to TVC](#deploy-to-tvc)
- [Turnkey org setup: users + policies](#turnkey-org-setup-users--policies)
- [Integration example](#integration-example)
- [Verifying the proofs](#verifying-the-proofs)
- [Configuration](#configuration)
- [Limitations & operational considerations](#limitations--operational-considerations)

---

## How it works

The quorum key is **stable across deployments** and exposed inside the enclave at
`/qos.quorum.key`. Two independent API keys are HKDF-derived from it:

```
prog_key  = P256(HKDF-SHA512(salt="tvc-cosign-programmatic-v1", ikm=quorum_seed))
admin_key = P256(HKDF-SHA512(salt="tvc-cosign-admin-v1",        ikm=quorum_seed))
```

Because the seed is stable, these public keys are stable and are registered as
Turnkey API users **once** (read them from `GET /pubkeys`). Classification:

- **PROGRAMMATIC**: an ERC-20 `transfer` whose token, recipient, and amount all
  pass the ruleset → stamped with `prog_key`.
- **ADMIN**: a privileged selector on the admin allowlist → stamped with
  `admin_key`.
- **REJECT**: anything else, or a signer not on the allowlist → `400`, no stamp.

Separately, each enclave has a per-boot **ephemeral key** (`/qos.ephemeral.key`,
one per replica) whose public half is attested in the enclave's **Boot Proof**.
Every `/cosign` response carries an **App Proof** signed by that key, committing
to the exact decision. See [Verifying the proofs](#verifying-the-proofs).

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness probe → `200 {"status":"ok"}` (required by TVC). |
| `GET /pubkeys` | `{ programmatic, admin }`: the two stamping public keys to register as API users. Stable across replicas; fetch once. |
| `POST /cosign` | In: `{ unsignedTransaction, signerAddress }`. Out: `{ activityBody, xStamp, classification, appProof, bootEphemeralKey }`. |

---

## Local development

```bash
# Build + run the full test suite (crypto is pinned by known-answer tests).
cargo test

# Create a ruleset from the example and run locally.
cp rules.example.toml rules.toml
cargo run -- --organization-id "$YOUR_ORG_ID" --rules-path rules.example.toml

# In another shell:
curl -s localhost:3000/health
curl -s localhost:3000/pubkeys | jq

# Cosign an ERC-20 transfer (matches rules.example.toml).
TX=02f862018080808094111111111111111111111111111111111111111180b844a9059cbb00000000000000000000000000000000000000000000000000000000000000ff00000000000000000000000000000000000000000000000000000000000001f4c0
curl -s -X POST localhost:3000/cosign -H 'content-type: application/json' \
  -d "{\"unsignedTransaction\":\"$TX\",\"signerAddress\":\"0x00000000000000000000000000000000000000a1\"}" | jq
```

> Outside an enclave, `/qos.quorum.key` and `/qos.ephemeral.key` are absent, so
> the app falls back to **insecure dev seeds** and warns loudly. The real keys
> (and therefore the registered pubkeys) only appear once deployed, read them
> from `GET /pubkeys` on the live enclave.

---

## Reproducible build

A TVC app boots by extracting and running **only the pivot binary** from the
container image (measured as `expectedPivotDigest`); the rest of the image
filesystem is never mounted in the enclave. The QOS manifest pins that binary's
digest, so if the binary changes between builds, even from identical source,
attestation fails. Because the container filesystem is not available at runtime,
the **ruleset is compiled into the binary** (`include_str!("rules.toml")`, see
`src/rules.rs`) rather than shipped as a file, which also means it is covered by
the attested `expectedPivotDigest`. Every build input is pinned:

| Input | How it's pinned |
|---|---|
| Rust toolchain | `rust:1.94-alpine` in `Dockerfile` (pin its `@sha256:` before deploying; see the comment in the file) |
| Runtime base | `stagex/core-busybox:1.36.1@sha256:cac5d773…` (StageX is itself reproducible) |
| Rust dependencies | `Cargo.lock`, committed; built with `--locked` |
| Ruleset | `rules.toml` compiled into the binary via `include_str!`, so it is covered by `expectedPivotDigest` |
| Symbols / paths | `[profile.release] strip = true` removes build-machine paths from the binary |

The runtime image ships **no ca-certificates and no libc**, the binary is static
and makes no egress (see [Limitations](#limitations--operational-considerations)).

### Step 1 — Set your ruleset (compiled into the binary)

`rules.toml` at the crate root is compiled into the binary at build time
(`include_str!`), so it becomes part of the attested `expectedPivotDigest` and is
present in the enclave (a file baked into the image would not be — TVC runs only
the pivot binary). Fill in your real allowlists before building:

```bash
cp rules.example.toml rules.toml && $EDITOR rules.toml
```

> `rules.toml` must exist at the crate root for the build to compile. Changing it
> changes the binary, and therefore `expectedPivotDigest`, which is exactly what
> makes the ruleset attestable.

Optionally pin the builder toolchain for a bit-for-bit reproducible build (see the
comment at the top of the `Dockerfile`), not required for a working deployment,
only for third parties to reproduce the exact binary digest.

### Step 2 — Build and push to a container registry

GHCR is used here only as an example. Any OCI-compliant registry works
(Docker Hub, Amazon ECR, GCP Artifact Registry, a self-hosted registry) as long
as TVC can pull the image **by digest** and it's a standard `linux/amd64` OCI
image. Substitute your registry host/namespace for `ghcr.io/YOUR_GITHUB_USERNAME`
throughout (and use that registry's login instead of `docker login ghcr.io`).

```bash
# Create a GitHub Personal Access Token with the `write:packages` scope:
#   https://github.com/settings/tokens/new?scopes=write:packages
# Read it without it landing in shell history (-s silences echo; `read` is a
# builtin so the value is never a command argument).
read -s GITHUB_TOKEN && export GITHUB_TOKEN
echo "$GITHUB_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin

# Build for linux/amd64 (required by Nitro Enclaves) and push.
# --provenance=false --sbom=false keeps the push a single image manifest instead of
# wrapping it in a multi-arch index, so there is exactly one digest to pin.
docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
  -t ghcr.io/YOUR_GITHUB_USERNAME/tvc-cosign:latest --push .
```

Make the package public so the enclave can pull it without a pull secret:
GitHub → Packages → `tvc-cosign` → Package settings → Change visibility → Public.
(If you keep it private, you must set `pivotContainerEncryptedPullSecret` in the
deploy config instead.)

### Step 3 — Capture the two digests

TVC pins **both** the container image and the pivot binary inside it.

```bash
# (a) Container image digest -> pivotContainerImageUrl. With the single-manifest
# build above, this is just the top-level `Digest:` (MediaType
# ...manifest.v2+json). If you built without --provenance=false, the output is an
# index instead and you pick the child whose line says `Platform: linux/amd64`.
docker buildx imagetools inspect ghcr.io/YOUR_GITHUB_USERNAME/tvc-cosign:latest
# → ghcr.io/YOUR_GITHUB_USERNAME/tvc-cosign@sha256:<digest>

# (b) Pivot binary digest -> expectedPivotDigest. The build already prints it as
# `expectedPivotDigest=sha256:...`; to recompute from the image:
docker create --platform linux/amd64 --name tvc-extract \
  ghcr.io/YOUR_GITHUB_USERNAME/tvc-cosign:latest /bin/true \
  && docker cp tvc-extract:/tvc-cosign ./tvc-cosign.bin && docker rm tvc-extract
sha256sum ./tvc-cosign.bin
```

> **Source provenance.** Build from a clean, committed tree and record the git
> commit (ideally an annotated tag) the image was built from, and publish it
> alongside the deployment, since nothing in the registry infers it. To verify:
> `git checkout <commit>`, rebuild Steps 1–3, and confirm the pivot binary
> `sha256` equals the `expectedPivotDigest` in the enclave's attested QOS manifest
> ([Verifying the proofs](#verifying-the-proofs)). With the builder pinned by
> digest + `Cargo.lock` + `--locked`, that binary digest is deterministic from the
> source. Note `rules.toml` is compiled into the binary (and is **not** committed,
> it is per-deployment), so it also determines the digest: to reproduce a specific
> deployment, a verifier needs both that commit **and** that deployment's exact
> `rules.toml`. Publish your `rules.toml` alongside the deployment if you want
> third parties to reproduce your `expectedPivotDigest`.

---

## Deploy to TVC

Requires the [`tvc` CLI](https://docs.turnkey.com/getting-started/verifiable-cloud-quickstart)
(`cargo install tvc`) and TVC access enabled for your org. The steps below are the
CLI flow; some parts (creating the app, creating the deployment) can also be done
from the Turnkey dashboard. See the
[Verifiable Cloud quickstart](https://docs.turnkey.com/features/verifiable-cloud/quickstart#create-your-first-verifiable-app)
for the dashboard walkthrough. Approval is always done via the `tvc` CLI.

### Step 4 — Create the TVC app

```bash
tvc login                                  # generates an operator keypair
tvc app init --output app.json             # set "name": "tvc-cosign"
tvc app create --config-file app.json
```

### Step 5 — Create the deployment

```bash
tvc deploy init                            # writes deploy-<timestamp>.json
```

Edit the generated `deploy-<timestamp>.json`:

```jsonc
{
  "qosVersion":             "0.12.0",       // LatestQosReleaseVersion
  "pivotContainerImageUrl": "ghcr.io/YOUR_GITHUB_USERNAME/tvc-cosign@sha256:<amd64-digest>",
  "pivotPath":              "/tvc-cosign",
  "pivotArgs":              ["--organization-id", "<YOUR_ORG_ID>", "--port", "3000"],
  "expectedPivotDigest":    "<sha256-binary-digest>",
  "healthCheckType":        "TVC_HEALTH_CHECK_TYPE_HTTP",
  "healthCheckPort":        3000,
  "publicIngressPort":      3000,
  "dangerousDeployDebugMode": false
  // remove pivotContainerEncryptedPullSecret (image is public, see below)
}
```

**On `pivotContainerEncryptedPullSecret`:** `tvc deploy init` always generates this
line with the placeholder `"<REMOVE_ME_IF_PIVOT_CONTAINER_URL_IS_PUBLIC>"`. It is
only needed to pull the image from a **private** registry. If your image is public,
delete the line entirely, otherwise `tvc deploy create` rejects the config with a
placeholder error. (If you keep the image private, supply the secret with
`--pivot-pull-secret <PATH>` instead.) In this demo we made the ghcr image public
in Step 2, so **remove the line**.

Also keep `dangerousDeployDebugMode: false` for any real deployment: debug mode
disables normal attestation enforcement (PCRs come back zeroed), which invalidates
the boot and app proofs.

```bash
tvc deploy create --config-file deploy-<timestamp>.json
# → prints Deployment ID and App ID; copy the Deployment ID.
```

`--organization-id` rides in `pivotArgs`, so it is recorded in the QOS manifest
and **attested**, so the deployment provably stamps only for that org. The ruleset
is compiled into the binary, covered by `expectedPivotDigest`. One deployment = one
org + one ruleset.

### Step 6 — Approve the manifest

Passing `--deploy-id` is enough: `tvc deploy approve` fetches the manifest for that
deployment (so it resolves the manifest ID itself) and resolves the operator ID and
operator seed from your logged-in tvc profile (`~/.config/turnkey`, where
`tvc app create` cached them). It then walks you through the interactive approval
and posts it.

```bash
tvc deploy approve --deploy-id <DEPLOY_ID>
```

You only need the extra flags in specific cases:

- `--operator-id <OPERATOR_ID>` if your profile has **more than one** saved operator
  (otherwise it auto-selects the single one, or prompts interactively). The operator
  ID is printed by `tvc app create` as "Manifest Set Operator IDs" and stored under
  `last_operator_ids` in `~/.config/turnkey`; it is **not** shown by `deploy status`.
- `--manifest-id <MANIFEST_ID>` only if you approve from a manifest file
  (`--manifest <path>`) instead of `--deploy-id`. When needed, the manifest ID *is*
  shown by `tvc deploy status --deploy-id <DEPLOY_ID>`.
- `--dangerous-skip-interactive` if you run without a TTY (CI); otherwise the
  interactive approval prompts require a terminal.

### Step 7 — Go live

The deployment reaches **LIVE** a few minutes after approval:

```bash
tvc deploy status --deploy-id <DEPLOY_ID>          # wait for LIVE
curl https://app-<APP_UUID>.turnkey.cloud/health   # → {"status":"ok"}
curl https://app-<APP_UUID>.turnkey.cloud/pubkeys  # the REAL stamping keys
```

The `/pubkeys` values are the quorum-derived keys you register as API users in
[Turnkey org setup](#turnkey-org-setup-users--policies).

---

## Turnkey org setup: users + policies

Do this once, against the org you passed as `--organization-id` (the org that owns
the signing wallets, the two API users, and the policies).

**1. A wallet** whose account address is your `signerAddress` / `signWith`
target, and which appears in `allowed_signers` in `rules.toml`.

**2. Two API-only users**, with API public keys taken verbatim from
`GET /pubkeys` on the live enclave (curve `API_KEY_CURVE_P256`):

| User | API public key |
|---|---|
| `TVC programmatic` | `pubkeys.programmatic` |
| `TVC admin` | `pubkeys.admin` |

**3. Two policies.** The engine is default-deny, so each policy only grants a
specific ALLOW. (Field syntax: [policy language](https://docs.turnkey.com/features/policies/language).)

Programmatic → auto-complete (self-consensus by the programmatic user):

```json
{
  "policyName": "TVC programmatic: allow signing",
  "effect": "EFFECT_ALLOW",
  "consensus": "approvers.any(user, user.id == '<TVC_PROGRAMMATIC_USER_ID>')",
  "condition": "activity.action == 'SIGN'"
}
```

Admin → require human consensus (holds at `CONSENSUS_NEEDED` until the named
humans approve; they get implicit approve permission by being in `consensus`):

```json
{
  "policyName": "TVC admin: require 2 human approvers",
  "effect": "EFFECT_ALLOW",
  "consensus": "approvers.any(user, user.id == '<TVC_ADMIN_USER_ID>') && approvers.any(user, user.id == '<HUMAN_ADMIN_1_ID>') && approvers.any(user, user.id == '<HUMAN_ADMIN_2_ID>')",
  "condition": "activity.action == 'SIGN'"
}
```

The two policies are disjoint by initiator: a programmatic-stamped activity never
matches the admin policy and vice-versa. To tighten further (belt-and-suspenders
with the enclave-side signer allowlist), extend `condition`, e.g.
`activity.action == 'SIGN' && wallet.id == '<WALLET_ID>'`, or scope by
`eth.tx.to`. For a larger human quorum, tag your approvers and use
`approvers.filter(user, user.tags.contains('<TAG_ID>')).count() >= N`.

---

## Integration example

The customer calls `/cosign`, then forwards the result to Turnkey. **Send
`activityBody` verbatim**, the stamp covers those exact bytes, so any
re-serialization breaks it. `classification` is informational (client-side only).

```bash
OUT=$(curl -s -X POST "$TVC_URL/cosign" -H 'content-type: application/json' \
  -d "{\"unsignedTransaction\":\"$TX\",\"signerAddress\":\"$SIGNER\"}")

curl -s https://api.turnkey.com/public/v1/submit/sign_transaction \
  -H 'Content-Type: application/json' \
  -H "X-Stamp: $(printf '%s' "$OUT" | jq -r .xStamp)" \
  --data "$(printf '%s' "$OUT" | jq -r .activityBody)"   # verbatim body
```

```javascript
const cosign = await fetch(`${TVC_URL}/cosign`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ unsignedTransaction, signerAddress }),
}).then((r) => r.json());

// Forward to Turnkey. activityBody is sent as-is; xStamp goes in the header.
const res = await fetch(
  "https://api.turnkey.com/public/v1/submit/sign_transaction",
  {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Stamp": cosign.xStamp },
    body: cosign.activityBody, // do NOT JSON.parse/stringify; send verbatim
  },
).then((r) => r.json());

switch (res.activity.status) {
  case "ACTIVITY_STATUS_COMPLETED": {
    const signed = res.activity.result.signTransactionResult.signedTransaction;
    // broadcast `signed`
    break;
  }
  case "ACTIVITY_STATUS_CONSENSUS_NEEDED": {
    // admin path: notify human approvers; poll get_activity or use webhooks.
    const activityId = res.activity.id;
    break;
  }
}
```

---

## Verifying the proofs

Every `/cosign` response includes an `appProof` and a `bootEphemeralKey`. Together
with the enclave's Boot Proof they prove that **this attested code classified this
transaction this way**, independent of Turnkey and of this app's operator.

`appProof` is the standard Turnkey App Proof envelope:

```json
{
  "scheme": "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
  "publicKey": "04…",                     // uncompressed SEC1 sign key (65 bytes)
  "proofPayload": "{\"type\":\"APP_PROOF_TYPE_COSIGN_DECISION\", …}",
  "signature": "30…"                       // P-256 / SHA-256 / DER over proofPayload
}
```

The `proofPayload` commits to `organizationId`, `signerAddress`,
`unsignedTransaction`, `classification`, `stampedWith` (which API key stamped),
and `activityBodySha256` (SHA-256 of the exact submitted body).

To verify:

1. **App Proof signature**: verify `signature` over the raw `proofPayload`
   string bytes (ECDSA P-256, SHA-256) against `publicKey`. If it checks out, the
   decision is intact and was produced by the holder of that ephemeral key.
2. **Boot Proof**: fetch it for the replica that answered, using the response's
   `bootEphemeralKey` (per-replica; **use the value from the same response**):

   ```
   POST https://api.turnkey.com/public/v1/query/get_boot_proof
   { "organizationId": "<org>", "ephemeralKey": "<bootEphemeralKey>" }
   ```
3. **Link them**: `bootProof.ephemeralPublicKeyHex` ends with
   `appProof.publicKey` (the boot key is `encryptPub ‖ signPub`; the sign half is
   the App Proof key).
4. **Confirm the code**: `bootProof.awsAttestationDocB64` is an AWS-signed COSE
   document with the enclave's PCRs, and `bootProof.qosManifestB64` contains the
   pivot binary hash, compare it to your `expectedPivotDigest` from the build.

Turnkey publishes verification tooling so you don't hand-roll steps 1–4:
[`turnkey_proofs`](https://crates.io/crates/turnkey_proofs) (Rust),
[`@turnkey/crypto` `proof.ts`](https://github.com/tkhq/sdk/blob/main/packages/crypto/src/proof.ts)
(JS), and the [Go SDK](https://github.com/tkhq/go-sdk/tree/main/pkg/proofs).

> **Replicas.** A production TVC runs multiple replicas, each with its own
> ephemeral key, and requests are load-balanced across them. Always verify using
> the `appProof.publicKey` / `bootEphemeralKey` returned **in that same response**
> and never a cached one from a different call.

---

## Configuration

All runtime config is passed as CLI arguments (`pivotArgs` in a deployment). None
of it is secret; the only secrets are the enclave-provided key files.

| Argument | Default | Meaning |
|---|---|---|
| `--organization-id <id>` | none (warns, empty) | The org placed in every `SIGN_TRANSACTION_V2` body (owns the wallets + API users + policies). Attested via `pivotArgs`. |
| `--rules-path <path>` | embedded ruleset | **Local-dev override only.** Loads a ruleset TOML from disk instead of the one compiled into the binary; a deployment does not use this (the file would not exist in the enclave). If the path fails to load, the app falls back to the embedded ruleset, never to deny-all. |
| `--port <n>` | `3000` | Listen port (binds `0.0.0.0`). |

The ruleset a deployment enforces is the `rules.toml` **compiled into the binary**
(`include_str!`), covered by `expectedPivotDigest`. For local dev, `--rules-path` /
`TVC_RULES_PATH` can point at a different file, and `TVC_ORGANIZATION_ID` is honored
(a TVC deployment cannot inject env vars). See `rules.example.toml` for the ruleset
format: `allowed_signers`, and a `[programmatic]` block (`allowed_tokens`,
`allowed_recipients`, `max_amount`) plus `[admin] selectors`.

---

## Limitations & operational considerations

This is a POC. Known scope limits, all deliberate:

- **Quorum-key provisioning: the stamping keys are not yet secret.** TVC currently
  provisions every app with a **static, well-known quorum key** (custom
  provisioning is "coming soon"). The programmatic and admin stamping keys are
  HKDF-derived from that quorum key with public salts, so today anyone who knows
  the well-known quorum key can re-derive both private keys. The programmatic
  path's safety therefore does not rest on key secrecy: a party who derives the
  programmatic key could stamp an arbitrary `SIGN_TRANSACTION` that the
  programmatic policy (`activity.action == 'SIGN'`) allows, bypassing the enclave
  ruleset (the ruleset only binds when the enclave itself stamps). Separately, a
  quorum-key signature is not enclave-exclusive by design (the quorum key can be
  provisioned into any conforming enclave), which is why enclave-exclusivity comes
  from the **App Proof** (signed by the per-boot Ephemeral Key), not from the
  stamp. Treat this deployment as **testnet / demo only** until custom (secret)
  quorum-key provisioning is available; only then do the derived keys become
  secret and the "only the attested enclave can stamp" property hold. Interim
  mitigations: tighten the Turnkey programmatic policy (constrain `eth.tx.to` /
  wallet / chain) so a leaked key can sign less, and verify the App Proof
  out-of-band before acting on a stamp.
- **No caller authentication on `/cosign`.** Access is network-perimeter only.
  Anyone who can reach the endpoint can request a stamp; safety comes from the
  ruleset + the Turnkey-side policies, not from authenticating the caller. Put it
  behind your own authenticated ingress.
- **`max_amount` is a single global cap**, interpreted in the token's base units,
  it ignores per-token decimals and USD value. Easy extension: per-token caps in
  `rules.toml`.
- **No price/velocity/cumulative limits.** Each `/cosign` is stateless, so a
  per-transaction cap is not a spending limit. Rate/velocity limits would need
  state (in tension with the stateless, attestable design) or a Turnkey-side
  policy.
- **ERC-20 `transfer` only** for the programmatic path; native-ETH transfers and
  other selectors are REJECT (admin selectors excepted). Contract-creation is
  out of scope.
- **One deployment = one org + one ruleset.** New contracts/rules mean a new
  deployment (and a new attested image), not new individual policies.
- **No network egress, by design.** The app only stamps, so it needs nothing
  external; the image ships without ca-certificates. Egress would only be
  justified to add on-chain / sanctions / price-oracle rules, and TVC external
  connectivity is a separate feature.
- **Verification status.** The stamp construction is validated live against
  Turnkey, and the ephemeral-key / App-Proof construction is validated
  byte-for-byte against Turnkey's production reference. The full live round-trip
  (submit → policy outcome → Boot-Proof verification) is exercised once deployed
  to a real enclave.
