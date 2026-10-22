FROM node:24-bookworm@sha256:64af3819f9275802414d7cdc38c27e9d82bd564dec4d4da87d008255d36c63b4 AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv patchelf binutils ripgrep \
    && python3 -m venv /opt/packaging \
    && /opt/packaging/bin/pip install --no-cache-dir staticx==0.14.2
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY packaging ./packaging
RUN sh packaging/build.sh

FROM scratch AS binary
COPY --from=build /app/pivot /pivot

FROM scratch
COPY --from=build /app/pivot /pivot
WORKDIR /tmp
ENV HOST=0.0.0.0
EXPOSE 3000
ENTRYPOINT ["/pivot"]
