# Contract optimizer

The repository owns the Docker build recipe. CI builds and loads the image for
its own use; it does not publish an image or require registry credentials.

## Usage

From the repository root:

```sh
just optimize                             # build, optimize and validate all contracts
just optimizer-build                      # build just the image
sh docker/optimizer/run.sh ./contracts/chain-codec-solana  # one contract
```

All builds target `linux/amd64`, including on Apple Silicon (via Docker's
emulation). Output is `artifacts/*.wasm` plus
`artifacts/checksums.txt`; this directory is generated build output. Each
successful build replaces the previous contract artifact set.

## Pinned tools

- Upstream `cosmwasm/optimizer:0.17.0`, pinned by digest.
- A digest-pinned Debian Rust image. Rust 1.98.1 for contracts is selected
  inside the container independently of the repository's native toolchain.
- Binaryen 132, from the official Linux release, verified by SHA-256.
- `cosmwasm-check` 3.0.7, built in a separate pinned Rust 1.86.0
  Debian stage with `--locked`.
