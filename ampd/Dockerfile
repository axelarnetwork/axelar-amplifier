FROM rust:bookworm as build
WORKDIR /app
RUN apt-get update && apt-get install -y clang protobuf-compiler
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim AS final
COPY --from=build /app/target/release/ampd /usr/local/bin/ampd
COPY --from=build /app/ampd/config.toml /usr/local/bin/config.toml
WORKDIR /usr/local/bin
ENTRYPOINT ["ampd"]
