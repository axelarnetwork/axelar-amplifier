FROM rust:latest as build
WORKDIR /app

RUN apt-get update && apt-get install -y clang protobuf-compiler
COPY . .
RUN cargo build --release
