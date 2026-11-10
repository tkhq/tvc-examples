# Run an agent in a sandbox

An optional demo. It runs the [pi](https://github.com/badlogic/pi-mono) coding agent in a locked-down Docker container with two credentials, and neither is a long-lived secret:

- a GitHub installation token from the broker, narrowed to one repository and revoked when the container exits;
- a short-lived session token for a small model router on the host.

The model provider key stays in the router. The agent never sees it.

```
host:      router (holds the model key) ── gh-token (asks the TVC broker)
              ▲                                   │
container: pi ─┘  ROUTER_TOKEN, ROUTER_URL, GH_TOKEN
```

## Run it

You need Docker and a deployed or local broker (see [DEPLOY.md](DEPLOY.md)). Build the image once:

```sh
docker build -t tvc-gh-sandbox:local sandbox
```

Run it with the same environment as `client/src/demo.ts`, plus a file that holds a model provider key (OpenRouter by default):

```sh
export TURNKEY_ORGANIZATION_ID=<org id> USER_KEY_FILE=<minting user API key file>
export BROKER_URL=https://app-<app id>.app.turnkey.cloud INSTALLATION_ID=<id> REPOS=<lowercase repo>
MODEL_KEY_FILE=<provider key file> sandbox/pi.sh "Summarize the three latest commits of <owner>/<repo>."
```

Set `MODEL` to pick a model (default `anthropic/claude-haiku-5.5`). The router allows only that model. When the run ends, the script revokes the GitHub token and prints the router's log, one line per request.

## What the container gets

- Environment: `GH_TOKEN`, `ROUTER_TOKEN`, `ROUTER_URL`, `MODEL`. Nothing else.
- No Linux capabilities, `no-new-privileges`, a read-only root, a tmpfs home, and limits on processes and memory.
- The router URL, not the provider URL. Pi is pointed at it through a custom provider in `models.json`.

## What the router enforces

`sandbox/router.ts` accepts only `POST /v1/chat/completions` with a valid session token. It rejects models outside the allowlist, rejects the OpenRouter `models` fallback list, stops at a per-session request cap, adds the provider key, and streams the response back. The token expires after 30 minutes by default.

## Limits

- The router runs on the host, so the host process holds the model key. This shows the sandbox boundary and the token handling. It does not show enclave custody of the model key. A router that runs as a TVC app would close that gap.
- On Linux the launcher shares the host network with the container, because the bridge network cannot reach a loopback listener. This path is untested. On Docker Desktop the container uses `host.docker.internal`.
- The container has open network access, so the agent can send data to other hosts. Add egress rules if that matters.
