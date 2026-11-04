FROM node:20-bookworm-slim
ARG TARGETARCH
ARG GH_VERSION=2.74.2
ARG PI_VERSION=0.54.2
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz" \
    | tar -xz --strip-components=2 -C /usr/local/bin "gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh" \
 && npm install -g "@mariozechner/pi-coding-agent@${PI_VERSION}" \
 && npm cache clean --force
USER node
ENV HOME=/home/node GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 NO_COLOR=1
WORKDIR /home/node
