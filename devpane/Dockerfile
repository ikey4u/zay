# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM node:22-trixie@sha256:072889700aecef94c5cee46c6e60107cc2aaad9aa9e418ce05abaa1e85752ee3 AS node
FROM rust:1-trixie@sha256:5d05167b28cef0fa3a6c781cd77949386848191f3382e82cf53bd1277a47a98f AS build
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

FROM debian:13@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 netcat-openbsd chromium iputils-ping dnsutils traceroute procps \
    && rm -rf /var/lib/apt/lists/*

# Pin the CJK font package and use HTTPS DNS to avoid host VPN FakeIPs at build time.
RUN curl --fail --silent --show-error --location --ipv4 --retry 2 \
    --connect-timeout 10 --max-time 120 \
    --doh-url https://dns.alidns.com/dns-query --resolve dns.alidns.com:443:223.5.5.5 \
    https://mirrors.tuna.tsinghua.edu.cn/debian/pool/main/f/fonts-noto-cjk/fonts-noto-cjk_20240730%2Brepack1-1_all.deb \
    -o /tmp/fonts-noto-cjk.deb \
    && echo 'f5dc28a754e17327d99f0a612134d92c8dd6187314ae967cb77f25df60860139  /tmp/fonts-noto-cjk.deb' | sha256sum -c - \
    && dpkg -i /tmp/fonts-noto-cjk.deb \
    && rm /tmp/fonts-noto-cjk.deb

COPY --from=build /usr/local/bin/zay /usr/local/bin/zay
COPY devpane/entrypoint-node.sh /usr/local/bin/devpane-node
COPY devpane/entrypoint-relay.sh /usr/local/bin/devpane-relay
COPY devpane/zay.toml /etc/zay/zay.toml
RUN chmod 755 /usr/local/bin/zay /usr/local/bin/devpane-node /usr/local/bin/devpane-relay

EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/devpane-node"]
