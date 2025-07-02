# Project commands. Requires `just` to be installed.
# https://crates.io/crates/just

# Run rust optimizer for x86_64 architecture.
optimize:
    docker run --rm -v "$(pwd)":/code \
      --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
      --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
      cosmwasm/optimizer:0.16.1

# Run rust optimizer for arm64 architecture. Not recommended for production.
optimize-arm64:
    docker run --rm -v "$(pwd)":/code \
      --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
      --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
      cosmwasm/optimizer-arm64:0.16.1

# Run project checks.
check:
    cargo clippy --all-targets -- -D warnings -A deprecated
    cargo +nightly fmt --all --check
    cargo sort --workspace --check --check-format

# Run migration remover for a specific contract.
remove-migration contract:
    cargo run --bin migration-remover -- -c {{contract}}
