FROM rust:bookworm as build
WORKDIR /app
RUN apt-get update && apt-get install -y clang protobuf-compiler
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim AS final
COPY --from=build /app/target/release/ampd /usr/local/bin/ampd
WORKDIR /usr/local/bin
CMD ["ampd"]
