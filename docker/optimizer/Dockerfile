# Build with --platform linux/amd64, including on Apple Silicon.
FROM cosmwasm/optimizer:0.17.0@sha256:7e0b9229c1a4118d0c9a2af2e7f5d95a91f264c26a2ce5681c779926e74d7f85 AS upstream

# Build the checker with the existing compiler on glibc. Wasmer on Alpine
# requires static Clang libraries; Debian avoids that extra toolchain.
FROM rust:1.86.0-bookworm@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081 AS checker
RUN cargo +1.86.0 install cosmwasm-check --version 3.0.7 --locked \
    --root /opt/checker --jobs 2

FROM upstream AS binaryen
ADD --checksum=sha256:195ddc94f9bc89f45abdabb0b9eea86023d727ba90eac8b35b80f2544fc30572 \
    https://github.com/WebAssembly/binaryen/releases/download/version_132/binaryen-version_132-x86_64-linux.tar.gz /tmp/binaryen.tar.gz
RUN tar -xzf /tmp/binaryen.tar.gz -C /tmp binaryen-version_132/bin/wasm-opt \
    && /tmp/binaryen-version_132/bin/wasm-opt --version

FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS optimizer
RUN rustup target add wasm32-unknown-unknown
ENV RUSTUP_TOOLCHAIN=1.98.1
COPY --from=upstream /usr/local/bin/bob /usr/local/bin/bob
COPY --from=binaryen /tmp/binaryen-version_132/bin/wasm-opt /usr/local/bin/wasm-opt
COPY --from=checker /opt/checker/bin/cosmwasm-check /usr/local/bin/cosmwasm-check
COPY --chmod=755 optimize.sh /usr/local/bin/optimize.sh
WORKDIR /code
ENTRYPOINT ["/usr/local/bin/optimize.sh"]
CMD ["."]
