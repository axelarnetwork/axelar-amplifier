FROM rust:1.74-bookworm as builder
RUN apt-get update && apt-get install -y clang protobuf-compiler

WORKDIR /ampd
COPY ./Cargo.toml ./Cargo.toml
COPY ./ampd/Cargo.toml ./ampd/Cargo.toml
COPY ./ampd/Cargo.lock ./ampd/Cargo.lock
COPY ./packages ./packages
COPY ./contracts ./contracts
COPY ./integration-tests ./integration-tests
COPY ./.cargo ./.cargo

# build dependencies separately
RUN mkdir ampd/src && echo 'fn main() {}' > ampd/src/main.rs
RUN cargo build --release

COPY ./ampd/proto ./ampd/proto
COPY ./ampd/src ./ampd/src
COPY ./ampd/build.rs ./ampd/build.rs

RUN cargo install --locked --path ./ampd

FROM debian:bookworm-slim AS runner
RUN addgroup --system --gid 1001 axelard && adduser --home /home/axelard --system --uid 1000 --ingroup axelard axelard
WORKDIR /home/axelard
RUN mkdir /.ampd && chown axelard /.ampd
USER axelard
COPY --from=builder /ampd/target/release/ampd /usr/local/bin
COPY ./entrypoint.sh ./

ENTRYPOINT ["./entrypoint.sh"]
