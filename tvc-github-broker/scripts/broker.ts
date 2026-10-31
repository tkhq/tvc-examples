/** Helpers to build and start the broker binary for the demo. */
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

export const ROOT = path.resolve(import.meta.dir, "..");
const BROKER_BIN = path.join(ROOT, "src/target/debug/github-broker");

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

export function ensureBrokerBuilt() {
  if (fs.existsSync(BROKER_BIN) && process.env.REBUILD !== "1") return;
  const r = Bun.spawnSync(["cargo", "build", "--bin", "github-broker"], { cwd: path.join(ROOT, "src"), stdout: "inherit", stderr: "inherit" });
  if (r.exitCode !== 0) throw new Error("cargo build failed");
}

type Broker = { url: string; stop: () => void };

/** Start the broker and wait until `/health` answers. Its logs go to stderr. */
export async function spawnBroker(configPath: string, apiKeyPath: string, port: number): Promise<Broker> {
  const proc = Bun.spawn([BROKER_BIN, "--host", "127.0.0.1", "--port", String(port), "--config", configPath, "--turnkey-api-key-path", apiKeyPath], {
    stdout: "inherit",
    stderr: "inherit",
    env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? "info", NO_COLOR: "1" },
  });
  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) throw new Error(`broker exited with ${proc.exitCode}`);
    try {
      if ((await fetch(`${url}/health`)).ok) return { url, stop: () => proc.kill() };
    } catch {
      /* not up yet */
    }
    await Bun.sleep(100);
  }
  proc.kill();
  throw new Error("broker did not start");
}
