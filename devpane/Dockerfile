FROM debian:13

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Binary is produced by devpane/be/manage.sh and stripped before this copy.
COPY .build/zay /usr/local/bin/zay
COPY entrypoint-node.sh /usr/local/bin/devpane-node
COPY entrypoint-relay.sh /usr/local/bin/devpane-relay
COPY zay.toml /etc/zay/zay.toml
RUN chmod 755 /usr/local/bin/zay /usr/local/bin/devpane-node /usr/local/bin/devpane-relay

EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/devpane-node"]
