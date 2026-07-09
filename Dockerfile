# syntax=docker/dockerfile:1
# ── Build stage ──────────────────────────────────────────────────────────────
# Reproducible builds require pinning every input by digest. Before an attestable
# deployment, pin this image:
#   docker pull rust:1.94-alpine
#   docker inspect rust:1.94-alpine --format='{{index .RepoDigests 0}}'
# then append the resulting @sha256:... to the FROM line below. Keep the Rust
# version aligned with rust-toolchain / your local toolchain for output parity.
FROM rust:1.94-alpine AS builder

# musl-dev supplies the headers + static C runtime the linker needs. Alpine's
# default target is x86_64-unknown-linux-musl, so cargo produces a fully static
# binary with no libc dependency.
RUN apk add --no-cache musl-dev

WORKDIR /app
# Copy only what the build needs (see .dockerignore) so the image can't pick up
# stray host files and the digest stays a function of the committed source.
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# --locked builds against the committed Cargo.lock exactly (no dependency drift).
RUN cargo build --release --locked

# ── Runtime stage ────────────────────────────────────────────────────────────
# StageX busybox is itself reproducibly built and provides the /bin/sh that TVC's
# containerd requires to start the task. There are deliberately NO ca-certificates
# and no libc: the binary is static and makes ZERO network egress — it only stamps
# requests, so it has nothing to reach out to. That is a security property, not an
# omission (see README "No egress").
FROM stagex/core-busybox:1.36.1@sha256:cac5d773db1c69b832d022c469ccf5f52daf223b91166e6866d42d6983a3b374

COPY --from=builder /app/target/release/tvc-cosign /tvc-cosign

# The ruleset is baked into the image so it is covered by the image digest — i.e.
# attested as part of the deployment. Create ./rules.toml from rules.example.toml
# (with your real allowlists) before building.
COPY rules.toml /rules.toml

# Print the pivot binary digest at build time. This is the `expectedPivotDigest`
# you record in the TVC deployment manifest.
RUN sha256sum /tvc-cosign | awk '{print "expectedPivotDigest=sha256:" $1}'

EXPOSE 3000

# For local `docker run`. In a TVC deployment these are overridden by the
# manifest's pivotPath (/tvc-cosign) + pivotArgs, where you also add
# --organization-id <your-sub-org-id> (see README Step 6).
ENTRYPOINT ["/tvc-cosign"]
CMD ["--rules-path", "/rules.toml", "--port", "3000"]
