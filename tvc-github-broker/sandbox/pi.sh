#!/usr/bin/env bash
# Run pi in the hardened sandbox. The model key stays in the host router; the
# container gets a router URL, a session token, and a narrowed GitHub token.
#   sandbox/pi.sh "task for the agent"
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export MODEL="${MODEL:-anthropic/claude-haiku-5.5}" PORT="${PORT:-18787}"
tmp="$(mktemp -d)"; umask 077
KEY_FILE="${MODEL_KEY_FILE:?set MODEL_KEY_FILE}" SESSION_OUT="$tmp/session" ALLOWED_MODELS="$MODEL" HOST="${ROUTER_HOST:-127.0.0.1}" \
  bun "$here/router.ts" 2>"$tmp/router.log" &
router=$!
# Docker Desktop resolves host.docker.internal to the host. On Linux the bridge
# network cannot reach a loopback listener, so share the host network instead.
if [ "$(uname -s)" = Linux ]; then net=(--network host); host=127.0.0.1; else net=(); host=host.docker.internal; fi
export GH_TOKEN ROUTER_TOKEN ROUTER_URL="http://$host:$PORT/v1"
cleanup() {
  kill "$router" 2>/dev/null || true
  curl -s -o /dev/null -w "revoke GitHub token: HTTP %{http_code}\n" -X DELETE -H "Authorization: Bearer ${GH_TOKEN:-}" -H "Accept: application/vnd.github+json" https://api.github.com/installation/token >&2 || true
  echo "--- router log" >&2; cat "$tmp/router.log" >&2; rm -rf "$tmp"
}
trap cleanup EXIT
for _ in $(seq 1 50); do [ -s "$tmp/session" ] && break; sleep 0.1; done
ROUTER_TOKEN="$(cat "$tmp/session")"
GH_TOKEN="$(bun "$here/gh-token.ts")"
docker run --rm -i --init ${net[@]+"${net[@]}"} \
  --cap-drop ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp --tmpfs /home/node:uid=1000,gid=1000,mode=700 \
  --pids-limit 256 --memory 1g \
  -e GH_TOKEN -e ROUTER_TOKEN -e ROUTER_URL -e MODEL \
  tvc-gh-sandbox:local sh -c '
    mkdir -p "$HOME/.pi/agent"
    printf "{\"providers\":{\"router\":{\"baseUrl\":\"%s\",\"api\":\"openai-completions\",\"apiKey\":\"ROUTER_TOKEN\",\"models\":[{\"id\":\"%s\"}]}}}" "$ROUTER_URL" "$MODEL" > "$HOME/.pi/agent/models.json"
    exec pi --provider router --model "$MODEL" --no-session -p "$@"
  ' sh "$@"
