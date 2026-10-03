# syntax=docker/dockerfile:1
FROM rust:1-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && strip target/release/devpane-be

FROM debian:13
COPY --from=build /src/target/release/devpane-be /usr/local/bin/devpane-be
EXPOSE 8090 3128 53/udp 80
ENTRYPOINT ["/usr/local/bin/devpane-be"]
