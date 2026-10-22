# Pivot packaging

Reviewed 2026-10-22: TypeScript checking and esbuild bundling pass. An existing
`dist/pivot` is a static Linux AMD64 ELF. Docker was unavailable during this
review, so its build provenance and scratch execution still need verification.

Application code under `src/` uses normal Node APIs. Everything specific to
single-executable distribution lives here and in the multi-stage Dockerfile.

1. esbuild bundles the TypeScript server and dependencies into one CommonJS file.
2. Node's [single executable application](https://nodejs.org/api/single-executable-applications.html)
   support and postject embed it in a copy of the Node runtime.
3. [StaticX](https://staticx.readthedocs.io/en/latest/introduction.html) bundles the
   ELF loader and system libraries behind a statically linked bootloader.
4. The `binary` Docker target exports just `/pivot`; the final scratch image lets
   you exercise that same executable with no installed runtime.

StaticX extracts its embedded libraries to temporary storage before execution.
Supply writable, executable `/tmp` (or `TMPDIR`) and a mounted `/proc`. These are
runtime filesystem requirements; no image files or package downloads are needed
at startup. Node's built-in CA roots are included. The packaging-only `--self-test`
mode verifies DNS and HTTPS against GitHub without credentials.

That probe does not exercise the broker's MCP handler. With the packaged server
running and `BROKER_TOKEN` exported, check health, rejected unauthenticated access,
and authenticated discovery without issuing a credential:

```sh
node packaging/smoke.mjs http://127.0.0.1:3000/mcp
```

Finally use `client.ts` against the packaged server to verify actual GitHub
issuance and revocation. Hash `/pivot` from the exact image you publish; an
independent rebuild/export is not evidence of that image's binary digest.

The build image is pinned by digest and npm dependencies are locked. Debian and
packaging-tool dependencies are not fully reproducibly pinned; this example does
not promise bit-identical rebuilds. Hash the exact exported pivot you deploy.

With OCI runtime support, replace these build steps with a normal Node image and
`npm start`. The broker code and environment contract stay unchanged.
