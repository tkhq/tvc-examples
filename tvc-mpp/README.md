# TVC MPP computation worker

A persistent TVC application that evaluates a synthetic eligibility record and
returns a verifiable App Proof. A separate Cloudflare gateway handles Web Bot
Auth and MPP settlement, then calls this worker with a short-lived OAuth access
token issued by the Turnkey identity service.

The worker holds no OAuth issuer signing key and issues no access tokens. Its
only signing operation produces App Proofs with the QOS ephemeral key.

## Flow and trust boundaries

```text
Agent → Cloudflare gateway → Turnkey OAuth token endpoint
             │
             ├─ verify Web Bot Auth and settle MPP
             │
             └─ OAuth access token + computation input → TVC worker
                                                        │
Agent ← result + App Proof ←─────────────────────────────┘
```

The gateway is trusted to enforce payment and supply the verified bot key and
payment challenge identifiers. The worker's App Proof commits to the exact
input bytes and computation result, together with that supplied context. It
does not independently attest settlement or custody of the agent's key.

The client independently verifies the App Proof and linked Boot Proof against
an approved non-debug TVC manifest and PCR policy. A valid P-256 signature by
itself does not establish that a computation ran in an enclave.

## Endpoints

`GET /health` returns `{"status":"healthy"}`. It confirms that the process
loaded its keys and public authorization policy; it does not establish OAuth
grant availability or a completed payment.

`POST /v1/evaluate` requires `Authorization: Bearer <access token>` and an
`application/json` body of at most 16 KiB:

```json
{
  "jobId": "demo-001",
  "record": { "ageYears": 25, "country": "US" },
  "context": {
    "mppChallengeId": "payment-challenge-id",
    "botKeyId": "verified-web-bot-key-thumbprint"
  }
}
```

The input uses synthetic data. `jobId` is 1–64 ASCII letters, digits, underscores
or hyphens; `ageYears` is an integer from 0 through 130; `country` is two
uppercase ASCII letters. Unknown fields and duplicate fields are rejected.
Eligibility requires age at least 18 and country `US`. Rejection reasons are
`under_age` and `unsupported_country`, in that order.

The response is:

```json
{
  "result": { "eligible": true, "reasons": [] },
  "proof": {
    "scheme": "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
    "publicKey": "<QOS ephemeral public key hex>",
    "proofPayload": "<exact signed JSON bytes>",
    "signature": "<P-256 signature hex>"
  }
}
```

The signed payload has type `APP_PROOF_TYPE_MPP_EVALUATION_V1` and includes
`timestampMs`, `jobId`, SHA-256 `inputDigest` of the exact received body bytes,
`result`, `mppChallengeId`, and `botKeyId`. QOS signs the UTF-8 payload with its
normal P-256/SHA-256 operation. No extra digest is signed a second time.

## OAuth resource-server contract

The deployment configures one exact trusted HTTPS issuer, public JWKS, HTTPS
audience origin, client ID, and required scope (`evaluate` by default).
The worker checks:

- ES256 signature and `typ: at+jwt`, using the published
  `turnkey_jwt_verify` 0.18.0 implementation.
- Exact `iss`, `client_id`, and `aud`. A single-element audience array is
  accepted; additional audiences are refused.
- Nonempty `sub`, required scope as a complete OAuth scope token, `iat`, `exp`,
  optional `nbf`, at most five seconds of skew, and a maximum lifetime of
  300 seconds.
- Absence of `cnf`: DPoP and certificate-bound resource tokens require their
  own sender-proof validation and are not silently treated as bearer tokens.

The public key set can include other signing algorithms; only its ES256/P-256
subset is eligible. Selected keys undergo the SDK's point, algorithm, usage,
private-material, and RFC 7638 thumbprint checks. Obtain this public set from
the trusted issuer's JWKS endpoint and review it with the deployment policy.
The worker does not fetch URLs taken from token headers.

Bearer access tokens authorize multiple calls until expiry. MPP credential
replay is enforced by the gateway; the worker does not make access tokens
single-use or claim request-bound OAuth authorization. Use TLS for this hop.

The live demo depends on the first-party Turnkey identity service issuing the
required access token through an enabled OAuth grant. Its JWKS being reachable
does not establish that grant issuance is available. Do not replace the issuer
with a local test signer or place a long-lived Turnkey API private key in the
Cloudflare environment to bypass an unavailable grant.

## Local validation

```sh
make test
make lint
```

Tests generate disposable local issuer and QOS keys in memory. They verify the
actual JWT validation path, refusal cases, input bounds, deterministic result,
and App Proof signature. These fixtures are test-only and have no AWS
attestation. Local tests do not establish a completed live OAuth or payment
flow.

## Build the delivery image

```sh
make image
```

This builds a Linux/amd64 OCI layout at `out/tvc-mpp` with `/tvc_app` as the
static binary. StageX base images are pinned by digest and Rust dependencies by
the committed lockfile. Docker needs BuildKit and the containerd image store,
following the other examples in this repository.

The scoped image workflow builds and checks this artifact without publishing.
Its summary records the extracted binary digest. Publish reviewed demo images
through the private `demo-mpp` repository to a pre-existing private registry
package. Public repository linkage can change package visibility; do not rely
on a new package default. The public source repository holds no registry write
permission for this build.

Pin the published immutable image digest and extracted binary digest when
creating a TVC deployment; a mutable image tag is insufficient.

## Deploy a persistent TVC app

Create a TVC app with its own private quorum and hosted operators. Disable debug
deployments. Set the deployment's pivot to `/tvc_app`, health check to HTTP on
port 44020, and public ingress to port 44020. QOS supplies the ephemeral and
quorum key files. This worker needs no outbound network access.

Use these pivot arguments with the approved public issuer configuration:

```json
[
  "--host", "0.0.0.0",
  "--port", "44020",
  "--issuer", "https://id.turnkey.com/t/<issuer-org-uuid>",
  "--audience", "https://<worker-public-origin>",
  "--client-id", "<registered-oauth-client-id>",
  "--required-scope", "evaluate",
  "--jwks-base64", "<base64-encoded-public-jwks-json>"
]
```

These are public settings, not an authorization-server private key. The
manifest binds them to the deployment. The key paths default to
`/qos.ephemeral.key` and `/qos.quorum.key`; custom paths can be supplied with
`--ephemeral-file` and `--quorum-file`. For local authenticated runs,
`--jwks-file` can replace `--jwks-base64`.

After manifest approval and attestation verification, provision the quorum and
wait for the deployment to be live. Verify `/health` and confirm that an
unauthenticated `/v1/evaluate` is rejected. These are availability and
authorization-rejection probes; record an authenticated evaluation and live
proof verification separately once OAuth issuance is available.

Store the full Boot Proof returned by Turnkey's GetBootProof API, then prepare
an independently approved manifest/PCR policy for the demo client. Do not
construct the client's trusted measurements from an unverified response.
Changing issuer configuration or pinned keys requires a new approved manifest
and corresponding client trust-policy update.
