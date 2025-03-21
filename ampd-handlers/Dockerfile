FROM rust:1.81-bookworm as builder

WORKDIR /ampd-handlers
COPY . .
RUN cargo build --release --bin sample_handler

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/sample_handler /usr/local/bin/
ENTRYPOINT ["sample_handler"]