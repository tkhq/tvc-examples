/**
 * Starts the whole local stack: the Turnkey shim (MINT_JWT + Secrets), the
 * mock GitHub API, and the broker binary. The App key is a throwaway RSA-2048
 * key, imported into the shim through the real SDK `importSecret` path; the
 * broker exports it at startup.
 */
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { Turnkey } from "@turnkey/sdk-server";
import { generateThrowawayPem, importAppKey } from "../admin/src/appkey.ts";
import { readApiKeyFile } from "../admin/src/turnkey.ts";
import { startShim, type Shim } from "../shim/src/server.ts";
import { initState } from "../shim/src/state.ts";
import { startMockGitHub, type MockGitHub } from "./mock-github.ts";

export const ROOT = path.resolve(import.meta.dir, "..");
export const BROKER_BIN = path.join(ROOT, "src/target/debug/github-broker");
export const APP_CLIENT_ID = "Iv23liMockDemo";
export const OWNER = "demo-owner";
export const INSTALLATION_ID = "12345";

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
    s.on("error", reject);
  });
}

export type Broker = { url: string; proc: ReturnType<typeof Bun.spawn>; logs: () => string; stop: () => void };

export type Stack = {
  dir: string;
  audience: string;
  organizationId: string;
  shim: Shim;
  github: MockGitHub;
  broker: Broker;
  secretId: string;
  keyFingerprint: string;
  keys: { alice: string; bob: string; broker: string; root: string };
  config: Record<string, any>;
  configPath: string;
  brokerPort: number;
  startBroker: (config?: Record<string, any>, port?: number) => Promise<{ broker?: Broker; exitCode?: number; logs: string }>;
  stop: () => void;
};

export function ensureBrokerBuilt() {
  if (!fs.existsSync(BROKER_BIN) || process.env.REBUILD === "1") {
    const r = Bun.spawnSync(["cargo", "build", "--bin", "github-broker"], { cwd: path.join(ROOT, "src"), stdout: "inherit", stderr: "inherit" });
    if (r.exitCode !== 0) throw new Error("cargo build failed");
  }
}

export async function spawnBroker(configPath: string, apiKeyPath: string, port: number, quiet: boolean): Promise<{ broker?: Broker; exitCode?: number; logs: string }> {
  let out = "";
  const proc = Bun.spawn([BROKER_BIN, "--host", "127.0.0.1", "--port", String(port), "--config", configPath, "--turnkey-api-key-path", apiKeyPath], {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? "info", NO_COLOR: "1" },
  });
  const pump = async (s: ReadableStream<Uint8Array>) => {
    const reader = s.getReader();
    for (;;) {
      const { value: chunk, done } = await reader.read();
      if (done) break;
      const t = new TextDecoder().decode(chunk);
      out += t;
      if (!quiet) process.stderr.write(t.replace(/^/gm, "[broker] "));
    }
  };
  void pump(proc.stdout as ReadableStream<Uint8Array>);
  void pump(proc.stderr as ReadableStream<Uint8Array>);
  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      await Bun.sleep(100);
      return { exitCode: proc.exitCode, logs: out };
    }
    try {
      if ((await fetch(`${url}/health`)).ok) {
        return { broker: { url, proc, logs: () => out, stop: () => proc.kill() }, logs: out };
      }
    } catch {
      /* not up yet */
    }
    await Bun.sleep(100);
  }
  proc.kill();
  throw new Error(`broker did not start:\n${out}`);
}

/** Use real Turnkey Secret Storage for the App key instead of the shim. */
export type LiveSecrets = {
  apiBaseUrl: string;
  organizationId: string;
  secretId: string;
  signerPublicKey: string;
  brokerApiKeyPath: string;
  appPublicKeyPem: string;
  keyFingerprint: string;
};

export async function startStack(o: { quiet?: boolean; liveSecrets?: LiveSecrets } = {}): Promise<Stack> {
  ensureBrokerBuilt();
  const quiet = o.quiet ?? true;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tvc-github-broker-"));
  const stateDir = path.join(dir, "shim");
  const brokerPort = await freePort();
  const audience = `http://127.0.0.1:${brokerPort}`;
  await initState({ dir: stateDir, audience, installationId: INSTALLATION_ID });
  const shim = await startShim({ stateDir, log: quiet ? () => {} : undefined });
  const organizationId = shim.state.org.organizationId;

  let secretId: string, fingerprint: string, publicSpkiPem: string;
  if (o.liveSecrets) {
    ({ secretId, keyFingerprint: fingerprint, appPublicKeyPem: publicSpkiPem } = o.liveSecrets);
  } else {
    // Throwaway App key, imported through the SDK into the shim's Secrets API.
    const k = generateThrowawayPem();
    publicSpkiPem = k.publicSpkiPem;
    const pemPath = path.join(dir, "throwaway-app-key.pem");
    fs.writeFileSync(pemPath, k.pem, { mode: 0o600 });
    const root = readApiKeyFile(path.join(stateDir, "keys/root.json"));
    const client = new Turnkey({ apiBaseUrl: shim.url, apiPublicKey: root.publicKey, apiPrivateKey: root.privateKey, defaultOrganizationId: organizationId }).apiClient();
    ({ secretId, fingerprint } = await importAppKey({ client, organizationId, pemPath, appClientId: APP_CLIENT_ID, signerPublicKey: shim.state.enclaveSignerPublicKey }));
    fs.rmSync(pemPath);
  }

  const github = await startMockGitHub({ publicKeyPem: publicSpkiPem, appClientId: APP_CLIENT_ID, owner: OWNER, installations: { [INSTALLATION_ID]: { repositories: ["demo", "demo-2", "secret-repo"] } } });

  const topLevelOrganizationId = shim.state.org.parentOrganizationId;
  if (topLevelOrganizationId === undefined) throw new Error("shim org has no parentOrganizationId; the broker config needs organization_id");
  const jwksPath = path.join(dir, "jwks.json");
  fs.writeFileSync(jwksPath, JSON.stringify(shim.state.jwks));
  const config = {
    audience,
    organization_id: topLevelOrganizationId,
    detailed_auth_errors: true,
    trusted_jwks_path: jwksPath,
    clock_skew_seconds: 5,
    github: { api_base_url: github.url, app_client_id: APP_CLIENT_ID, expected_key_sha256: fingerprint },
    turnkey: o.liveSecrets
      ? { api_base_url: o.liveSecrets.apiBaseUrl, organization_id: o.liveSecrets.organizationId, secret_id: secretId, signer_public_key: o.liveSecrets.signerPublicKey }
      : { api_base_url: shim.url, organization_id: organizationId, secret_id: secretId, signer_public_key: shim.state.enclaveSignerPublicKey },
    installations: { [INSTALLATION_ID]: { repositories: ["demo", "demo-2"], permissions: { contents: "read", issues: "write", metadata: "read" } } },
  };
  const configPath = path.join(dir, "broker-config.json");
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  const keys = Object.fromEntries(["alice", "bob", "broker", "root"].map((k) => [k, path.join(stateDir, "keys", `${k}.json`)])) as Stack["keys"];
  if (o.liveSecrets) keys.broker = o.liveSecrets.brokerApiKeyPath;

  const startBroker = async (cfg: Record<string, any> = config, port?: number) => {
    const p = path.join(dir, `broker-config-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    fs.writeFileSync(p, JSON.stringify(cfg, null, 2));
    return spawnBroker(p, keys.broker, port ?? (await freePort()), quiet);
  };
  const started = await spawnBroker(configPath, keys.broker, brokerPort, quiet);
  if (!started.broker) throw new Error(`broker exited ${started.exitCode}:\n${started.logs}`);

  return {
    dir,
    audience,
    organizationId,
    shim,
    github,
    broker: started.broker,
    secretId,
    keyFingerprint: fingerprint,
    keys,
    config,
    configPath,
    brokerPort,
    startBroker,
    stop: () => {
      started.broker?.stop();
      github.stop();
      shim.stop();
      if (process.env.KEEP_TMP !== "1") fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
