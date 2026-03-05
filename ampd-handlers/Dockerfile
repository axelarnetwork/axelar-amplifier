# Build stage
# Rust version should match rust-toolchain.toml
FROM rust:1.86-bookworm AS builder
RUN apt-get update && apt-get install -y clang protobuf-compiler cmake

WORKDIR /app
COPY . .

# Build argument to specify which handler to build
ARG HANDLER=evm

RUN cargo build --release --bin ${HANDLER}-handler

FROM debian:bookworm-slim AS runner
ARG GRPCURL_VERSION=1.9.3
ARG HANDLER=evm
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN GRPCURL_ARCH=$(case "${TARGETARCH}" in arm64) echo "arm64" ;; *) echo "x86_64" ;; esac) \
    && wget https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_${GRPCURL_ARCH}.tar.gz \
    && tar -xvf grpcurl_${GRPCURL_VERSION}_linux_${GRPCURL_ARCH}.tar.gz \
    && mv grpcurl /usr/local/bin/grpcurl \
    && chmod +x /usr/local/bin/grpcurl \
    && rm grpcurl_${GRPCURL_VERSION}_linux_${GRPCURL_ARCH}.tar.gz

COPY --from=builder /app/target/release/${HANDLER}-handler /usr/local/bin/ampd_handler
ENTRYPOINT ["ampd_handler"]
