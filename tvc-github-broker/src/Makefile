HOST ?= 127.0.0.1
PORT ?= 44020

.PHONY: all
all: build

.PHONY: build
build:
	cargo build --all

.PHONY: test
test: build
	cargo test --all-targets

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: lint
lint:
	cargo clippy --version
	cargo clippy --all-targets -- -D warnings

.PHONY: run
run:
	cargo run --bin github-broker -- \
	--host $(HOST) \
	--port $(PORT)
