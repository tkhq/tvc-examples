# Pivot packaging

Reviewed 2026-10-22: all seven Python tests and the installed dependency check
pass. An existing `dist/pivot` is a static Linux AMD64 ELF. Docker was unavailable
during this review, so its build provenance and scratch execution still need
verification.

`broker.py` and `server.py` use ordinary Python APIs. Everything specific to
single-executable distribution lives here and in the multi-stage Dockerfile.

1. [PyInstaller](https://pyinstaller.org/en/stable/operating-mode.html) embeds
   CPython, application modules, native extensions, and package data in one file.
2. [StaticX](https://staticx.readthedocs.io/en/latest/introduction.html) adds the
   ELF loader and remaining system libraries behind a static bootloader.
3. The `binary` Docker target exports just `/pivot`; the final scratch image lets
   you exercise it without an installed Python runtime or system libraries.

PyInstaller alone would still depend on the host's ELF loader and libc. StaticX
includes those too. Both tools unpack their embedded files at startup, so provide
writable, executable `/tmp` (or `TMPDIR`) and a mounted `/proc`. The extracted
files stay within the enclave; nothing is downloaded at startup. PyInstaller's
certifi hook includes the CA roots used by the GitHub HTTP client.

`entry.py` adds a packaging-only `--self-test` mode that checks imports, DNS, and
HTTPS to GitHub without credentials. The normal entrypoint remains `server.py`.
Imports are collected normally, with explicit data/metadata and Uvicorn hooks.
The optional MCP development CLI is not needed in the executable.

The self-test does not exercise the broker's MCP handler. Run `client.py` against
the packaged server to verify actual GitHub issuance and revocation. The
TypeScript example also includes an optional read-only
[`packaging/smoke.mjs`](../../tvc-github-broker-ts/packaging/smoke.mjs) that checks
health, rejected unauthenticated access, and authenticated discovery for either
broker. Hash `/pivot` from the exact image you publish; an independent
rebuild/export is not evidence of that image's binary digest.

The build image is pinned by digest and application dependencies are locked.
Debian packages and transitive build-tool dependencies are not fully pinned;
this example does not promise bit-identical rebuilds. Hash the exported pivot
you actually deploy.

With OCI support, install `requirements.lock` in a normal Python image and run
`python server.py`. The broker code and environment contract stay unchanged.
