# Project commands. Requires `just` to be installed.
# https://crates.io/crates/just

# Run rust optimizer for x86_64 architecture.
optimize:
    docker run --rm -v "$(pwd)":/code \
      --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
      --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
      cosmwasm/optimizer:0.17.0

# Run rust optimizer for arm64 architecture. Not recommended for production.
optimize-arm64:
    docker run --rm -v "$(pwd)":/code \
      --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
      --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
      cosmwasm/optimizer-arm64:0.17.0

# Run project checks.
check:
    cargo clippy-check
    cargo +nightly fmt-check
    cargo sort-check --grouped

# Run migration remover for a specific contract.
remove-migration contract:
    cargo run --bin migration-remover -- -c {{ contract }}
