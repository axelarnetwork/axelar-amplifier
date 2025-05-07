FROM rust:1.81-bookworm as builder

WORKDIR /app
COPY . .

# Build the ampd-handlers binary
RUN cargo build --release --bin ampd-handlers

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ampd-handlers /usr/local/bin/ampd_handler
ENTRYPOINT ["ampd_handler"]
