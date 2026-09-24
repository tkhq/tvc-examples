# TVC Signed ETH/USD Oracle Demo

A demonstration single-source oracle built on [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com). The TVC workload fetches CoinGecko's first-party, API3-compatible signed ETH/USD observation, verifies its publisher signature, and publishes it to Ethereum Sepolia with a policy-constrained Turnkey wallet.

The Solidity contract repeats the same signature verification on-chain and stores only the latest price and its provenance metadata. A valid signature proves that CoinGecko authorized the observation; it does not prove that the reported market price is economically correct.

---

## Contents

- [Trust boundaries](#trust-boundaries)
- [Endpoints](#endpoints)
- [Getting the code](#getting-the-code)
- [Prerequisites](#prerequisites)
- [Development](#development)
- [Building the TVC delivery image](#building-the-tvc-delivery-image)
- [Project structure](#project-structure)

---

## Trust boundaries

- **CoinGecko:** signs the ETH/USD value, template ID, and source timestamp.
- **TVC workload:** fetches the signed payload, checks CoinGecko's current signer certification, verifies the signature, and runs the daily update loop.
- **Turnkey policy:** permits the dedicated workload identity to sign only the expected Sepolia `updatePrice` call, with zero value, bounded gas fees, and the exact CoinGecko template ID.
- **Oracle contract:** independently verifies the signed payload, freshness, template, signer, and updater authorization.
- **Contract administrator:** may rotate the trusted CoinGecko signer or designated TVC updater. The updater cannot change either trust setting.

## Endpoints

The root page is a small dashboard that reads the canonical value from the Sepolia contract. The remaining endpoints are deliberately narrow:

```sh
$ curl localhost:44020/health
{"status":"healthy"}

$ curl localhost:44020/oracle/observation
{
  "source": "CoinGecko",
  "pair": "ETH/USD",
  "priceUsd": "2391.34",
  "priceUsdE18": "2391340000000000000000",
  "sourceTimestamp": 1788382236,
  "airnode": "0x9dB03a07bE313B3C08261B1d1606D511f3560D9e",
  "templateId": "0xdeda2f7938bf877d2f011aa550852d3459794e16944ea0b7513465479752ba93",
  "beaconId": "0x478a1bccb55fd03b0ef6a401fdfc86431e9abd7cb6ef456b505d9a13fbcb324d",
  "payloadHash": "0x...",
  "verified": true
}

$ curl localhost:44020/oracle/status
{
  "network": "Ethereum Sepolia",
  "source": "CoinGecko Signed API",
  "pair": "ETH/USD",
  "contract": {
    "latestPriceUsd": "2391.34",
    "sourceTimestamp": 1788382236,
    "recordedAt": 1788382300
  },
  "runtime": {
    "enabled": true,
    "updateIntervalSeconds": 86400,
    "phase": "waiting"
  }
}

$ curl localhost:44020/app-proof
{"payload":{"random_number":12345},"proof":{"public_key":"...","payload":"...","signature":"..."}}

$ curl localhost:44020/metrics
# HELP tvc_http_request_duration_ms HTTP request duration in milliseconds
# TYPE tvc_http_request_duration_ms histogram
tvc_http_request_duration_ms_bucket{method="GET",path="/health",status="200",le="1"} 1
...
```

## Getting the code

This example lives in the [`tkhq/tvc-examples`](https://github.com/tkhq/tvc-examples) monorepo. You can clone the whole repo, or just this example.

**Option 1 — clone the whole monorepo** (gets every example):

```sh
git clone https://github.com/tkhq/tvc-examples.git
cd tvc-examples/tvc-oracle
```

**Option 2 — clone just this example** (sparse checkout skips the other examples):

```sh
git clone --depth 1 --filter=blob:none --sparse https://github.com/tkhq/tvc-examples.git
cd tvc-examples
git sparse-checkout set tvc-oracle
cd tvc-oracle
```

## Prerequisites

- Rust 1.94 (installed automatically from `rust-toolchain.toml` when using rustup)
- Foundry, for the Solidity contract tests
- Docker 26 or newer with the containerd image store, for building the TVC delivery image
- A Turnkey account with TVC access, for deployment

## Development

### Run tests

```
make test
```

### Smart contract

The contract project uses Foundry and pins OpenZeppelin Contracts v5.7.0.

```sh
cd contracts
forge install OpenZeppelin/openzeppelin-contracts@v5.7.0 --no-git
forge test
```

`SignedEthUsdOracle` validates a real CoinGecko-signed fixture in its test suite and rejects unauthorized, replayed, stale, future-dated, wrong-template, wrong-signer, and non-positive observations.

#### Sepolia deployment

- Contract: [`0x9890Df3894EbF1dbCD8E69aA7fafFBA089d8BF6b`](https://sepolia.etherscan.io/address/0x9890Df3894EbF1dbCD8E69aA7fafFBA089d8BF6b)
- Deployment transaction: [`0x686cdf722b98c6643d71e904fe06a0908b257cce916573741b894246a30935e3`](https://sepolia.etherscan.io/tx/0x686cdf722b98c6643d71e904fe06a0908b257cce916573741b894246a30935e3)
- Administrator: `0xB4e170cE5c45b8DE195Df35D57F873CE6e0D9F5C`
- Updater: `0x13A586dDB307E183aB167D4fB4a67536F8891D2f`
- Constructor-patched runtime Keccak-256: `0xadbd6dc26b606dd08104f9bf8168461832e5b6dd6479a48d9dbc1aed6d1999fb`

The deployed runtime bytes match an independently reproduced local deployment with the same constructor arguments.

### Run locally

```
make run
```

Server starts on http://127.0.0.1:44020

Autonomous updates are disabled locally by default. TVC enables them explicitly:

```sh
/tvc_app --host 0.0.0.0 --port 3000 --oracle-updates --oracle-update-interval-seconds 86400
```

The updater checks the contract before spending gas, retries transient failures after 15 minutes, and waits for a successful Sepolia receipt. For this demo, deploy one replica so there is one scheduler for the shared updater account.

## Building the TVC delivery image

TVC executes and verifies the statically linked ELF binary at `/tvc_app`. The OCI image is the delivery envelope used to publish that binary; the deployment manifest pins both the image digest and the binary's SHA-256 digest.

The monorepo's `Build TVC Oracle image` GitHub Actions workflow builds a single-platform `linux/amd64` StageX image, publishes it to `ghcr.io/<repository-owner>/tvc-oracle-demo`, and prints the exact TVC deployment values in the workflow summary.

### Optional local build

This repository uses [StageX](https://stagex.tools) to build OCI containers. Requires Docker >= 26 with containerd:

- **Docker Desktop:** Dashboard > Settings > "Use containerd for pulling and storing images"
- **Linux:** add to `/etc/docker/daemon.json`:
  ```json
  {
    "features": {
      "containerd-snapshotter": true
    }
  }
  ```

Build the container:

```sh
make out/tvc-oracle-demo/index.json
```

## Project structure

```
crates/
  admin-cli/      # Explicit local administrator signing utility
  tvc-oracle-demo/  # Oracle updater, status API, and dashboard binary
  metrics/        # Prometheus metrics Tower middleware
  e2e/            # End-to-end tests
images/
  tvc-oracle-demo/  # Containerfile for OCI image
contracts/
  src/            # Solidity oracle contract
  test/           # Foundry contract tests
```
