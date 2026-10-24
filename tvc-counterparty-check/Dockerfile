# TVC runs exactly one file from this image: the pivot binary at pivotPath. It is
# copied into the enclave and executed there with an empty environment and no
# container filesystem, so it must be a single, fully static executable.
#
# This Dockerfile produces one from the TypeScript source:
#   1. esbuild bundles src/ and its dependencies into one JavaScript file.
#   2. Node's single executable application (SEA) support turns that bundle
#      into a blob, which postject injects into a fully static Node 24 binary
#      (pkg-fetch's "linuxstatic" build, pinned by SHA-256).
# The result is /tvc_app. The build stage runs on the host's native platform;
# the output is always linux/amd64. The runtime stage only carries /tvc_app and
# the /bin/sh TVC uses to copy it out.
#
# To refresh the Node image digest:
#   docker pull --platform linux/amd64 node:24-alpine
#   docker inspect node:24-alpine --format='{{index .RepoDigests 0}}'
FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# Fully static Node 24 for linux/amd64, pinned by SHA-256.
# Source: https://github.com/yao-pkg/pkg-fetch/releases/tag/v3.6
ARG STATIC_NODE_VERSION=v24.20.0
ARG STATIC_NODE_SHA256=83223146550e6dce2e773e1668b397aab63664e820ac40551f9df16b0d8b276f
RUN wget -q -O /static-node https://github.com/yao-pkg/pkg-fetch/releases/download/v3.6/node-${STATIC_NODE_VERSION}-linuxstatic-x64 \
  && echo "${STATIC_NODE_SHA256}  /static-node" | sha256sum -c - \
  && chmod +x /static-node

COPY sea-config.json ./
COPY src ./src
RUN npx esbuild src/server.ts --bundle --platform=node --target=node24 --format=cjs \
      --outfile=dist/server.cjs --external:pg-native --log-level=warning \
  && node --experimental-sea-config sea-config.json \
  && cp /static-node /tvc_app \
  && npx postject /tvc_app NODE_SEA_BLOB dist/sea-prep.blob \
       --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2

# ── Runtime ─────────────────────────────────────────────────────────────────
# busybox supplies the /bin/sh TVC needs to extract the pivot. Nothing else in
# this image reaches the enclave.
FROM stagex/core-busybox:1.36.1@sha256:cac5d773db1c69b832d022c469ccf5f52daf223b91166e6866d42d6983a3b374

COPY --from=build /tvc_app /tvc_app

# This is expectedPivotDigest for the deployment manifest.
RUN sha256sum /tvc_app | awk '{print "expectedPivotDigest=" $1}'

EXPOSE 3000

# In a TVC deployment these become pivotPath (/tvc_app) + pivotArgs, where you
# also add --database-url (and optionally --database-ca-file).
ENTRYPOINT ["/tvc_app"]
CMD ["--port", "3000"]
