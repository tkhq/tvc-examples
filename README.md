# tvc-examples

Example applications built on [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com/features/verifiable-cloud/overview), a platform for running your own code inside AWS Nitro Enclaves with cryptographic proof of exactly what ran.

This repository is a **monorepo**. Each example is a self-contained project in its own top-level directory, with its own README and setup instructions.

## Examples

- [tvc-chainalysis](tvc-chainalysis/README.md): Sanctions screening with a TVC app and web frontend.
- [tvc-cosign](tvc-cosign/README.md): Classify EVM transactions and stamp Turnkey requests.
- [tvc-policy-sidecar](tvc-policy-sidecar/README.md): Verify Turnkey activity webhooks and vote on signing requests of chains without parsing-support.

## Getting the code

Each example lives in the `tkhq/tvc-examples` monorepo. You can clone the whole repo, or just one example.

**Option 1: clone the whole monorepo (gets every example):**

```
git clone https://github.com/tkhq/tvc-examples.git
cd tvc-examples/<example-name>
```

**Option 2: clone just one example (sparse checkout skips the other examples):**

```
git clone --depth 1 --filter=blob:none --sparse https://github.com/tkhq/tvc-examples.git
cd tvc-examples
git sparse-checkout set <example-name>
cd <example-name>
```

Once you're in an example directory, follow its own README for setup and deploy instructions.

## Learn more

- [Turnkey Verifiable Cloud overview](https://docs.turnkey.com/features/verifiable-cloud/overview)
- [Turnkey docs](https://docs.turnkey.com)
