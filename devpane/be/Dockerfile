FROM debian:13

COPY .build/devpane-be /usr/local/bin/devpane-be
RUN chmod 755 /usr/local/bin/devpane-be

EXPOSE 8090 3128 53/udp 80
ENTRYPOINT ["/usr/local/bin/devpane-be"]
