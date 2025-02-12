FROM rust:1.81-bookworm as builder
RUN apt-get update && apt-get install -y clang protobuf-compiler cmake

WORKDIR /ampd
COPY . .

RUN --mount=type=cache,target=/ampd/target/ \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo install --locked --path ./ampd && cp /ampd/target/release/ampd /usr/local/bin

FROM debian:bookworm-slim AS runner
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
RUN addgroup --system --gid 1001 axelard && adduser --home /home/axelard --system --uid 1000 --ingroup axelard axelard
WORKDIR /home/axelard
RUN mkdir /.ampd && chown axelard /.ampd
USER axelard
COPY --from=builder /usr/local/bin/ampd /usr/local/bin
COPY ./entrypoint.sh ./

ENTRYPOINT ["./entrypoint.sh"]
