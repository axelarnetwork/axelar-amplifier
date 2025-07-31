FROM rust:1.86-bookworm AS builder
RUN apt-get update && apt-get install -y clang protobuf-compiler cmake

WORKDIR /app
COPY . .

# Build the ampd-handlers binary
RUN cargo build --release --bin ampd-handlers

FROM debian:bookworm-slim AS runner
ARG GRPCURL_VERSION=1.9.3

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz \
    && tar -xvf grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz \
    && mv grpcurl /usr/local/bin/grpcurl \
    && chmod +x /usr/local/bin/grpcurl \
    && rm grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz

COPY --from=builder /app/target/release/ampd-handlers /usr/local/bin/ampd_handler
ENTRYPOINT ["ampd_handler"]
