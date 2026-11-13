.PHONY: build test lint image

build:
	cargo build --locked

test:
	cargo test --locked --all-targets

lint:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings

image: out/tvc-mpp/index.json

out/tvc-mpp/index.json: Cargo.toml Cargo.lock rust-toolchain.toml Containerfile $(shell find src -type f)
	mkdir -p out
	DOCKER_BUILDKIT=1 SOURCE_DATE_EPOCH=1 BUILDKIT_MULTIPLATFORM=1 \
		docker build --platform linux/amd64 \
		--build-arg SOURCE_DATE_EPOCH=1 \
		--tag tkhq-tvc-mpp/tvc-mpp:build \
		--label org.opencontainers.image.source=https://github.com/tkhq/tvc-examples \
		--provenance=false \
		--output 'type=oci,name=tkhq-tvc-mpp/tvc-mpp:build,tar=false,dest=out/tvc-mpp,rewrite-timestamp=true,force-compression=true' \
		-f Containerfile .
