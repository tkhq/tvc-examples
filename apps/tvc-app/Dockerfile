# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

# ca-certificates are needed for HTTPS egress (Chainalysis API call).
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o /tvc_app .

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
