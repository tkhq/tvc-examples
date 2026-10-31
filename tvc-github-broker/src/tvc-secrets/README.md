# tvc-secrets

Turnkey Secrets export client for TVC apps written in Rust.

## What it does

`SecretsClient::export_secret(secret_id)` runs one `EXPORT_SECRETS` in
process and returns the plaintext as `SecretBytes`, which zeroizes on drop:

1. Generates a P-256 HPKE target key in memory (Turnkey's
   `turnkey_enclave_encrypt` crate, pinned to 0.6.0).
2. Submits `ACTIVITY_TYPE_EXPORT_SECRETS` with that target key, stamped with
   the app user's API key (`X-Stamp`, `SIGNATURE_SCHEME_TK_API_P256`).
3. Polls `get_activity` while the activity is `CREATED` or `PENDING`.
   `CONSENSUS_NEEDED` becomes `SecretsError::ConsensusNeeded`, `REJECTED` and
   HTTP 401/403 become `SecretsError::Denied`, anything else
   `SecretsError::ActivityFailed` or `SecretsError::Api`.
4. Verifies the Signer enclave signature on the returned `ServerSendMsgV1`
   against the pinned Signer key, checks that the bundle's quorum key is the
   pinned one (`SecretsError::UnpinnedSignerKey` otherwise) and that the
   organization ID matches, then decrypts (`SecretsError::Verification` on
   any failure).

The plaintext is never logged or written to disk. Errors never contain
secret material.

## Public API

- `ApiKey::from_json(bytes)` or `ApiKey::from_private_hex(hex)`, and
  `ApiKey::stamp(body)`. The caller loads the key material; this crate never
  reads files.
- `SignerPublicKey::from_hex` (65-byte signing key or 130-byte quorum key).
- `SecretsConfig::new(api_base_url, organization_id, api_key,
  signer_public_key)`, with `poll_timeout` and `request_timeout` fields.
- `SecretsClient::new(config)`, `export_secret(secret_id) -> SecretBytes`,
  `api_key_public_hex()`.
- `SecretBytes` and `SecretString`: wrappers that zeroize on drop and print
  `[redacted]`.
- `SecretsError`: `InvalidConfig`, `InvalidApiKey`, `Transport`, `Denied`,
  `Api`, `ConsensusNeeded`, `ActivityFailed`, `BadResponse`,
  `UnpinnedSignerKey`, `Verification`.

## Trust assumptions

- **Pinned Signer key.** The bundle is trusted only because the Signer
  enclave signed it with the key in `SecretsConfig::signer_public_key`. The
  caller pins that key out of band (the SDK's production key, or the value
  `enclaveQuorumPublic` that your deployment reports). A bundle under another key
  fails with `UnpinnedSignerKey`.
- **Organization ID check.** The bundle names the organization it was
  exported from; it must equal `SecretsConfig::organization_id`.
- **The API key is the app's identity.** Turnkey policy decides whether that
  user may export the secret. Whoever holds the key can call `EXPORT_SECRETS`
  to a target key of their choice; keep it inside the enclave.
- **TLS.** `reqwest` with rustls and webpki roots, redirects off. In a TVC
  enclave, TLS must terminate inside the enclave so the host sees only
  ciphertext.

## Known gap

The export target is not bound to the enclave's attestation. Policy for
`EXPORT_SECRETS` can check the principal and the secret's static properties,
but not the target public key, so anyone who holds the app user's API key
can export the secret to a key they control. The fix is the planned
enclave-target export,
where Turnkey checks the NSM attestation document and the QOS manifest and
policy can match manifest fields. Until then, the API key is as sensitive as
the secrets it can export.

Zeroization is best effort: this crate zeroizes its own buffers, but copies
inside `turnkey_enclave_encrypt`, `serde_json`, and `reqwest` are not under
its control.
