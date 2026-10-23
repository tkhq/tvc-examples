# ── Build stage ────────────────────────────────────────────────────────────────
# Pin to a specific digest for reproducible builds.
# To refresh: run `docker pull <new-tag>` then `docker inspect <new-tag> --format='{{index .RepoDigests 0}}'` and update the FROM line below
FROM golang:1.26.4-alpine@sha256:7a3e50096189ad57c9f9f865e7e4aa8585ed1585248513dc5cda498e2f41812c AS builder

WORKDIR /app

# The only network calls at build time are `go mod download` against
# proxy.golang.org and sum.golang.org, and both chain to Google Trust Services
# roots. Verify them against the same pinned bundle the binary embeds (see
# ca-certificates.crt + //go:embed) rather than the Alpine ca-certificates
# package that golang:alpine ships, which still contains the compromised emSign
# roots. SSL_CERT_DIR must be set as well: without it Go also loads every cert
# under /etc/ssl/certs, so SSL_CERT_FILE alone would not narrow the trust set.
# GOPROXY overrides Go's default (https://proxy.golang.org,direct) to remove
# the `,direct` fallback, because a direct VCS fetch would hit hosts outside
# that pinned set.
COPY ca-certificates.crt ./
ENV SSL_CERT_FILE=/app/ca-certificates.crt \
    SSL_CERT_DIR=/nonexistent \
    GOPROXY=https://proxy.golang.org
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-w -s" -o /tvc_app .

# ── Runtime stage ───────────────────────────────────────────────────────────────
# busybox provides /bin/sh which TVC's containerd requires to start the task.
# The Go binary is fully static (CGO_ENABLED=0) so no libc needed.
FROM stagex/core-busybox:1.36.1@sha256:cac5d773db1c69b832d022c469ccf5f52daf223b91166e6866d42d6983a3b374

COPY --from=builder /tvc_app /tvc_app

# Print the binary digest at build time — copy this value for the TVC deployment.
RUN sha256sum /tvc_app | awk '{print "SHA256=" $1}'

EXPOSE 3000

ENTRYPOINT ["/tvc_app"]
CMD ["--port", "3000"]
