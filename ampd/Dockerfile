FROM rust:1.78-bookworm as builder
RUN apt-get update && apt-get install -y clang protobuf-compiler cmake

WORKDIR /ampd
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./ampd/Cargo.toml ./ampd/Cargo.toml
COPY ./packages ./packages
COPY ./contracts ./contracts
COPY ./interchain-token-service ./interchain-token-service
COPY ./integration-tests ./integration-tests
COPY ./external-gateways ./external-gateways
COPY ./.cargo ./.cargo

# build dependencies separately
RUN mkdir ampd/src && echo 'fn main() {}' > ampd/src/main.rs
RUN cargo build --release

COPY ./ampd/proto ./ampd/proto
COPY ./ampd/src ./ampd/src
COPY ./ampd/build.rs ./ampd/build.rs

RUN cargo install --locked --path ./ampd

FROM debian:bookworm-slim AS runner
RUN apt update && apt install libssl3
RUN addgroup --system --gid 1001 axelard && adduser --home /home/axelard --system --uid 1000 --ingroup axelard axelard
WORKDIR /home/axelard
RUN mkdir /.ampd && chown axelard /.ampd
USER axelard
COPY --from=builder /ampd/target/release/ampd /usr/local/bin
COPY ./entrypoint.sh ./

ENTRYPOINT ["./entrypoint.sh"]
