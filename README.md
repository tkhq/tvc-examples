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
cargo run -- --organization-id "$YOUR_SUB_ORG_ID" --rules-path rules.example.toml

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

A TVC app boots from a container image whose digest is committed to the
deployment, and the QOS manifest additionally pins the pivot binary's digest. If
the binary changes between builds, even from identical source, attestation
fails. Every build input is therefore pinned:

| Input | How it's pinned |
|---|---|
| Rust toolchain | `rust:1.94-alpine` in `Dockerfile` (pin its `@sha256:` before deploying; see the comment in the file) |
| Runtime base | `stagex/core-busybox:1.36.1@sha256:cac5d773…` (StageX is itself reproducible) |
| Rust dependencies | `Cargo.lock`, committed; built with `--locked` |
| Symbols / paths | `[profile.release] strip = true` removes build-machine paths from the binary |

The runtime image ships **no ca-certificates and no libc**, the binary is static
and makes no egress (see [Limitations](#limitations--operational-considerations)).

```bash
# Bake your real ruleset into the image (it becomes part of the attested digest).
cp rules.example.toml rules.toml && $EDITOR rules.toml

# Build + push for linux/amd64 (required by Nitro Enclaves).
docker buildx build --platform linux/amd64 \
  -t ghcr.io/YOUR_ORG/tvc-cosign:latest --push .

# The container image digest for the deployment (pick the linux/amd64 manifest):
docker buildx imagetools inspect ghcr.io/YOUR_ORG/tvc-cosign:latest
# → use ghcr.io/YOUR_ORG/tvc-cosign@sha256:<amd64-digest>

# The pivot binary digest (expectedPivotDigest). The build also prints this as
# an `expectedPivotDigest=sha256:...` line; to recompute from the pushed image:
docker create --name x ghcr.io/YOUR_ORG/tvc-cosign:latest /bin/true \
  && docker cp x:/tvc-cosign ./tvc-cosign.bin && docker rm x
sha256sum ./tvc-cosign.bin
```

---

## Deploy to TVC

Requires the [`tvc` CLI](https://docs.turnkey.com/getting-started/verifiable-cloud-quickstart)
(`cargo install tvc`) and TVC access enabled for your org.

```bash
tvc login                                  # generates an operator keypair
tvc app init --output app.json             # set "name": "tvc-cosign", then:
tvc app create --config-file app.json

tvc deploy init                            # edit the generated deploy-*.json:
#   qosVersion:              <from TVC docs/dashboard>
#   pivotContainerImageUrl:  ghcr.io/YOUR_ORG/tvc-cosign@sha256:<amd64-digest>
#   pivotPath:               /tvc-cosign
#   pivotArgs:               ["--organization-id","<YOUR_SUB_ORG_ID>",
#                             "--rules-path","/rules.toml","--port","3000"]
#   expectedPivotDigest:     sha256:<binary-digest>
#   healthCheckType:         TVC_HEALTH_CHECK_TYPE_HTTP
#   healthCheckPort:         3000
#   publicIngressPort:       3000
#   debugMode:               false
tvc deploy create --config-file deploy-<timestamp>.json
tvc deploy approve --deploy-id <DEPLOY_ID> --operator-id <OPERATOR_ID>
```

`--organization-id` is passed in `pivotArgs`, so it is recorded in the QOS
manifest and **attested**, so the deployment provably stamps only for that org. The
ruleset is baked into the image at `/rules.toml`, so it is covered by the image
digest. One deployment = one org + one ruleset.

Once **LIVE**, the app is reachable at `https://app-<APP_UUID>.turnkey.cloud`:

```bash
curl https://app-<APP_UUID>.turnkey.cloud/health   # → {"status":"ok"}
curl https://app-<APP_UUID>.turnkey.cloud/pubkeys  # the REAL stamping keys
```

---

## Turnkey org setup: users + policies

Do this once, against the sub-org you passed as `--organization-id`.

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
| `--organization-id <id>` | none (warns, empty) | The (sub-)org placed in every `SIGN_TRANSACTION_V2` body. Attested via `pivotArgs`. |
| `--rules-path <path>` | `rules.toml` | Ruleset TOML. Baked deployments pass `/rules.toml`. |
| `--port <n>` | `3000` | Listen port (binds `0.0.0.0`). |

For local dev, `TVC_ORGANIZATION_ID` and `TVC_RULES_PATH` env vars are honored as
fallbacks (a TVC deployment cannot inject env vars). See `rules.example.toml` for
the ruleset format: `allowed_signers`, and a `[programmatic]` block
(`allowed_tokens`, `allowed_recipients`, `max_amount`) plus `[admin] selectors`.

---

## Limitations & operational considerations

This is a POC. Known scope limits, all deliberate:

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
