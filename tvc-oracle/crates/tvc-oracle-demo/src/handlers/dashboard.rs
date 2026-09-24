//! Human-readable oracle dashboard and machine-readable status.

use crate::{
    oracle_status::OracleRuntimeStatus, oracle_updater, response::AppError, state::AppState,
};
use axum::{Json, extract::State, response::Html};
use serde::Serialize;

const CONTRACT_ADDRESS: &str = "0x9890Df3894EbF1dbCD8E69aA7fafFBA089d8BF6b";
const UPDATER_ADDRESS: &str = "0x13A586dDB307E183aB167D4fB4a67536F8891D2f";
const SOURCE_AIRNODE: &str = "0x9dB03a07bE313B3C08261B1d1606D511f3560D9e";
const TEMPLATE_ID: &str = "0xdeda2f7938bf877d2f011aa550852d3459794e16944ea0b7513465479752ba93";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OracleStatusResponse {
    network: &'static str,
    source: &'static str,
    pair: &'static str,
    contract_address: &'static str,
    updater_address: &'static str,
    source_airnode: &'static str,
    template_id: &'static str,
    contract: oracle_updater::ContractStatus,
    runtime: OracleRuntimeStatus,
}

pub(crate) async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

pub(crate) async fn oracle_status(
    State(state): State<AppState>,
) -> Result<Json<OracleStatusResponse>, AppError> {
    let contract = oracle_updater::fetch_contract_status(&state)
        .await
        .map_err(|error| AppError::bad_gateway(format!("failed to read Sepolia: {error}")))?;
    let runtime = state.oracle_status.read().await.clone();
    Ok(Json(OracleStatusResponse {
        network: "Ethereum Sepolia",
        source: "CoinGecko Signed API",
        pair: "ETH/USD",
        contract_address: CONTRACT_ADDRESS,
        updater_address: UPDATER_ADDRESS,
        source_airnode: SOURCE_AIRNODE,
        template_id: TEMPLATE_ID,
        contract,
        runtime,
    }))
}

const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>TVC Signed ETH/USD Oracle</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background:#0b0b0c; color:#f4f2ed; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:radial-gradient(circle at 80% 0,#29253f 0,transparent 34rem),#0b0b0c; }
    main { width:min(960px,calc(100% - 40px)); margin:0 auto; padding:72px 0; }
    .eyebrow { color:#a99cff; font-size:13px; font-weight:700; letter-spacing:.13em; text-transform:uppercase; }
    h1 { max-width:760px; margin:14px 0 18px; font-size:clamp(38px,7vw,72px); line-height:.98; letter-spacing:-.05em; }
    .intro { max-width:720px; color:#b9b6c0; font-size:18px; line-height:1.6; }
    .grid { display:grid; grid-template-columns:1.35fr 1fr; gap:18px; margin-top:42px; }
    .card { border:1px solid #34323a; border-radius:18px; padding:24px; background:rgba(24,23,27,.82); box-shadow:0 18px 60px #0005; }
    .price { font-size:clamp(44px,8vw,76px); font-weight:750; letter-spacing:-.05em; margin:10px 0; }
    .label { color:#8f8b96; font-size:13px; text-transform:uppercase; letter-spacing:.08em; }
    .value { margin-top:7px; font-size:16px; }
    .row { padding:15px 0; border-top:1px solid #302e35; }
    .row:first-child { border-top:0; padding-top:0; }
    .pill { display:inline-flex; gap:8px; align-items:center; border:1px solid #3c3943; padding:7px 10px; border-radius:99px; font-size:13px; }
    .dot { width:8px; height:8px; border-radius:50%; background:#a99cff; }
    a { color:#c7c0ff; text-decoration:none; }
    code { font-size:12px; color:#cbc7d2; overflow-wrap:anywhere; }
    .explain { margin-top:18px; line-height:1.6; color:#aaa6b0; }
    .error { color:#ff9d9d; }
    footer { margin-top:28px; color:#76727d; font-size:13px; }
    @media (max-width:720px) { main { padding:40px 0; } .grid { grid-template-columns:1fr; } }
  </style>
</head>
<body>
<main>
  <div class="eyebrow">Turnkey Verifiable Cloud demo</div>
  <h1>A signed price, carried on-chain.</h1>
  <p class="intro">A TVC enclave independently verifies CoinGecko's signed ETH/USD observation, asks a narrowly scoped Turnkey wallet to sign the update, and publishes the latest value to Ethereum Sepolia.</p>
  <section class="grid">
    <article class="card">
      <div class="label">Latest on-chain ETH/USD</div>
      <div class="price" id="price">Loading...</div>
      <div class="pill"><span class="dot"></span><span id="phase">Reading Sepolia</span></div>
      <div class="explain">The source signature proves who authorized the payload and that it was not changed. It does not prove that a single source's market price is economically correct.</div>
    </article>
    <article class="card">
      <div class="row"><div class="label">CoinGecko observed</div><div class="value" id="source-time">—</div></div>
      <div class="row"><div class="label">Recorded on Sepolia</div><div class="value" id="recorded-time">—</div></div>
      <div class="row"><div class="label">Update cadence</div><div class="value" id="cadence">—</div></div>
      <div class="row"><div class="label">Oracle contract</div><div class="value"><a id="contract" target="_blank" rel="noreferrer">View on Etherscan ↗</a></div></div>
    </article>
  </section>
  <section class="card" style="margin-top:18px">
    <div class="row"><div class="label">Source signer</div><code id="signer">—</code></div>
    <div class="row"><div class="label">Latest payload hash</div><code id="payload">—</code></div>
    <div class="row"><div class="label">Updater status</div><div class="value" id="runtime">—</div></div>
  </section>
  <footer>Source → cryptographic verification in TVC → policy-constrained Turnkey signature → Sepolia contract.</footer>
</main>
<script>
  const time = value => value ? new Date(value * 1000).toLocaleString() : 'No update recorded yet';
  async function refresh() {
    try {
      const response = await fetch('/oracle/status', { cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      document.querySelector('#price').textContent = data.contract.recordedAt ? `$${Number(data.contract.latestPriceUsd).toLocaleString(undefined,{maximumFractionDigits:2})}` : 'Awaiting first update';
      document.querySelector('#phase').textContent = data.runtime.enabled ? data.runtime.phase : 'Updater disabled';
      document.querySelector('#source-time').textContent = time(data.contract.sourceTimestamp);
      document.querySelector('#recorded-time').textContent = time(data.contract.recordedAt);
      document.querySelector('#cadence').textContent = data.runtime.enabled ? `${data.runtime.updateIntervalSeconds / 3600} hours` : 'Not enabled';
      document.querySelector('#contract').href = `https://sepolia.etherscan.io/address/${data.contractAddress}`;
      document.querySelector('#signer').textContent = data.sourceAirnode;
      document.querySelector('#payload').textContent = data.contract.latestPayloadHash;
      document.querySelector('#runtime').textContent = data.runtime.lastError ? `Retrying after: ${data.runtime.lastError}` : `Healthy · ${data.runtime.phase}`;
      document.querySelector('#runtime').className = data.runtime.lastError ? 'value error' : 'value';
    } catch (error) {
      document.querySelector('#phase').textContent = 'Status unavailable';
      document.querySelector('#runtime').textContent = error.message;
      document.querySelector('#runtime').className = 'value error';
    }
  }
  refresh(); setInterval(refresh, 30000);
</script>
</body>
</html>"#;
