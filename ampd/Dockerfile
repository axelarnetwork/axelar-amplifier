FROM rust:1.81-bookworm AS chef
RUN apt-get update && apt-get install -y clang protobuf-compiler cmake
RUN cargo install cargo-chef --locked
WORKDIR /ampd

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /ampd/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
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
