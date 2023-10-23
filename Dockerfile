FROM ubuntu:22.04

# installing requirements to get and extract prebuilt binaries
RUN apt-get update 
RUN apt install clang
RUN apt install protobuf-compiler
ENV LIBCLANG_PATH=/usr/lib/llvm-17/lib/

FROM rust:1.72
COPY . .
RUN cargo build

CMD ["./target/release/ampd"]
