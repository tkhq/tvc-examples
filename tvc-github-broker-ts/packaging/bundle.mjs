import { build } from "esbuild";

// Application sources know nothing about SEA or TVC. OCI can run src/main.ts
// directly (or plain tsc output) and omit this entire packaging directory.
await build({
  entryPoints: ["packaging/entry.ts"],
  outfile: "dist/broker.cjs",
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node24",
});
