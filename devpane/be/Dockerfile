# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM debian:13@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c
# Share the cached diagnostic runtime layer with the Zay lab image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 netcat-openbsd chromium iputils-ping dnsutils traceroute procps \
    && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
COPY devpane/.build/linux/${TARGETARCH}/devpane-be /usr/local/bin/devpane-be
EXPOSE 8090 3128 53/udp 80
ENTRYPOINT ["/usr/local/bin/devpane-be"]
