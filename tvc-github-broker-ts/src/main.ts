import * as z from "zod/v4";
import { configSchema, GitHubBroker } from "./broker.js";
import { createBrokerServer } from "./server.js";

async function main() {
  const config = configSchema.extend({
    BROKER_TOKEN: z.string().min(32),
    HOST: z.string().default("127.0.0.1"),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    PUBLIC_HOST: z.string().default("localhost"),
  }).parse(process.env);
  const app = createBrokerServer(new GitHubBroker(config), config.BROKER_TOKEN, config.PUBLIC_HOST);
  app.server.listen(config.PORT, config.HOST, () => console.log(`MCP broker listening on port ${config.PORT}`));
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => void app.close());
  }
}

void main().catch(() => {
  console.error("Startup failed. Check the required environment variables and RSA private key.");
  process.exitCode = 1;
});
