# Project commands. Requires `just` to be installed.
# https://crates.io/crates/just

# Build the repo-local contract optimizer. Docker caches installed tools.
optimizer-build:
    docker build --platform linux/amd64 -t axelar-amplifier-optimizer:local docker/optimizer

# Build, optimize and validate contracts using the same platform as CI.
optimize: optimizer-build
    sh docker/optimizer/run.sh

# Run project checks.
check:
    cargo clippy-check
    cargo +nightly fmt-check
    cargo sort-check --grouped

# Run migration remover for a specific contract.
remove-migration contract:
    cargo run --bin migration-remover -- -c {{ contract }}
