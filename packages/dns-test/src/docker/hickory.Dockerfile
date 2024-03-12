FROM rust:1-slim-bookworm

# libssl-dev + pkg-config = required to build hickory-dns with feature dnssec-openssl
RUN apt-get update && \
    apt-get install -y \
        libssl-dev \
        pkg-config \
        tshark

# `dns-test` will invoke `docker build` from a temporary directory that contains
# a clone of the hickory repository. `./src` here refers to that clone; not to
# any directory inside the `dns-test` repository
COPY ./src /usr/src/hickory
RUN cargo install --path /usr/src/hickory/bin --features dnssec-openssl,recursor --debug && \
    mkdir /etc/hickory
env RUST_LOG=debug
