# ── Build stage ────────────────────────────────────────────────────────────────
# Pin to a specific digest for reproducible builds.
# To refresh: run `docker pull <new-tag>` then `docker inspect <new-tag> --format='{{index .RepoDigests 0}}'` and update the FROM line below
FROM golang:1.26.4-alpine@sha256:7a3e50096189ad57c9f9f865e7e4aa8585ed1585248513dc5cda498e2f41812c AS builder

# ca-certificates are needed for HTTPS egress (Chainalysis API call).
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-w -s" -o /tvc_app .

# ── Runtime stage ───────────────────────────────────────────────────────────────
# busybox provides /bin/sh which TVC's containerd requires to start the task.
# The Go binary is fully static (CGO_ENABLED=0) so no libc needed.
FROM stagex/core-busybox:1.36.1@sha256:cac5d773db1c69b832d022c469ccf5f52daf223b91166e6866d42d6983a3b374

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /tvc_app /tvc_app

# Print the binary digest at build time — copy this value for the TVC deployment.
RUN sha256sum /tvc_app | awk '{print "SHA256=" $1}'

EXPOSE 3000

ENTRYPOINT ["/tvc_app"]
CMD ["--port", "3000"]
