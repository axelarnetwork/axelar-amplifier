FROM rust:1.81-bookworm as builder
RUN apt-get update && apt-get install -y clang protobuf-compiler cmake

WORKDIR /ampd
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./ampd/Cargo.toml ./ampd/Cargo.toml
COPY ./ampd-handlers ./ampd-handlers
COPY ./packages ./packages
COPY ./contracts ./contracts
COPY ./integration-tests ./integration-tests
COPY ./external-gateways ./external-gateways
COPY ./tools ./tools
COPY ./.cargo ./.cargo

# build dependencies separately
RUN mkdir ampd/src && echo 'fn main() {}' > ampd/src/main.rs
RUN cargo build --release

COPY ./ampd/proto ./ampd/proto
COPY ./ampd/src ./ampd/src
COPY ./ampd/build.rs ./ampd/build.rs

RUN cargo install --locked --path ./ampd

FROM debian:bookworm-slim AS runner
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    wget \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*
RUN addgroup --system --gid 1001 axelard && adduser --home /home/axelard --system --uid 1000 --ingroup axelard axelard
WORKDIR /home/axelard
RUN mkdir /.ampd && chown axelard /.ampd
USER axelard
COPY --from=builder /ampd/target/release/ampd /usr/local/bin
COPY ./entrypoint.sh ./

ENTRYPOINT ["./entrypoint.sh"]
