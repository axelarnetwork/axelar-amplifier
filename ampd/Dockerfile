FROM rust:1.81-bookworm as builder
RUN apt-get update && apt-get install -y clang protobuf-compiler cmake

WORKDIR /ampd
COPY . .

RUN cargo install --locked --path ./ampd

FROM debian:bookworm-slim AS runner
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
RUN addgroup --system --gid 1001 axelard && adduser --home /home/axelard --system --uid 1000 --ingroup axelard axelard
WORKDIR /home/axelard
RUN mkdir /.ampd && chown axelard /.ampd
USER axelard
COPY --from=builder /ampd/target/release/ampd /usr/local/bin
COPY ./entrypoint.sh ./

ENTRYPOINT ["./entrypoint.sh"]
