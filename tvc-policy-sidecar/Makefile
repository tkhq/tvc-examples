HOST ?= 127.0.0.1
PORT ?= 44020
LOCAL_ENCLAVE_DIR ?= /tmp/policy-sidecar-local-enclave
EPHEMERAL_FILE ?= $(LOCAL_ENCLAVE_DIR)/qos.ephemeral.key
QUORUM_FILE ?= $(LOCAL_ENCLAVE_DIR)/qos.quorum.key
TURNKEY_ORGANIZATION_ID ?= local-organization-id
TURNKEY_API_BASE_URL ?= https://api.turnkey.com

.PHONY: all
all: build

.PHONY: build
build:
	cargo build --workspace --locked

.PHONY: test
test:
	cargo test --workspace --all-targets --locked

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: lint
lint:
	cargo clippy --workspace --all-targets --locked -- -D warnings

# Generate keys to simulate QOS control.
.PHONY: local-keys
local-keys:
	mkdir -p "$(LOCAL_ENCLAVE_DIR)"
	test -f "$(EPHEMERAL_FILE)" || openssl rand -hex 32 > "$(EPHEMERAL_FILE)"
	test -f "$(QUORUM_FILE)" || openssl rand -hex 32 > "$(QUORUM_FILE)"

.PHONY: run
run: local-keys
	cargo run --locked --bin policy-sidecar -- \
	--host "$(HOST)" \
	--port "$(PORT)" \
	--ephemeral-file "$(EPHEMERAL_FILE)" \
	--quorum-file "$(QUORUM_FILE)" \
	--turnkey-organization-id "$(TURNKEY_ORGANIZATION_ID)" \
	--turnkey-api-base-url "$(TURNKEY_API_BASE_URL)"
