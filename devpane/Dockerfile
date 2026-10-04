# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
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

ARG TARGETARCH
COPY devpane/.build/linux/${TARGETARCH}/zay /usr/local/bin/zay
COPY devpane/entrypoint-node.sh /usr/local/bin/devpane-node
COPY devpane/entrypoint-relay.sh /usr/local/bin/devpane-relay
COPY devpane/zay.toml /etc/zay/zay.toml
RUN chmod 755 /usr/local/bin/zay /usr/local/bin/devpane-node /usr/local/bin/devpane-relay

EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/devpane-node"]
