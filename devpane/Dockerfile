# syntax=docker/dockerfile:1
FROM node:22-trixie AS node
FROM rust:1-trixie AS build
COPY --from=node /usr/local/ /usr/local/
# Debian ships google/protobuf/*.proto in libprotobuf-dev, not protobuf-compiler.
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev cmake clang libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY client/webui/package*.json ./client/webui/
RUN cd client/webui && npm ci
COPY . .
ARG TARGETARCH
# Keep Linux build products in Docker, separate from native host builds.
RUN --mount=type=cache,id=devpane-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=devpane-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=devpane-target-${TARGETARCH},target=/src/target,sharing=locked \
    cargo build --locked -p zay --bin zay \
    && cp target/debug/zay /usr/local/bin/zay \
    && strip --strip-unneeded /usr/local/bin/zay

FROM debian:13

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 netcat-openbsd chromium iputils-ping dnsutils traceroute procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/zay /usr/local/bin/zay
COPY devpane/entrypoint-node.sh /usr/local/bin/devpane-node
COPY devpane/entrypoint-relay.sh /usr/local/bin/devpane-relay
COPY devpane/zay.toml /etc/zay/zay.toml
RUN chmod 755 /usr/local/bin/zay /usr/local/bin/devpane-node /usr/local/bin/devpane-relay

EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/devpane-node"]
