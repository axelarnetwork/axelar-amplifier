#!/bin/sh
set -eu

if [ "$#" -gt 1 ] || [ ! -d "${1:-.}" ]; then
    echo "Usage: optimize.sh [project-directory]" >&2
    exit 1
fi
project_dir=${1:-.}

rustc --version
cargo --version
wasm-opt --version
cosmwasm-check --version

# Upstream bob sets RUSTFLAGS itself. Encoded flags take precedence, retaining
# stripping and restoring the implicit host imports used by cosmwasm-std 2.x.
export CARGO_ENCODED_RUSTFLAGS="$(printf '%s\037%s' '-Clink-arg=-s' '-Clink-arg=--allow-undefined')"

# Do not include contracts left in the target cache by an earlier build.
rm -f /target/wasm32-unknown-unknown/release/*.wasm
(cd "$project_dir" && /usr/local/bin/bob)

set -- /target/wasm32-unknown-unknown/release/*.wasm
if [ ! -f "$1" ]; then
    echo "No Wasm contracts were built" >&2
    exit 1
fi

mkdir -p artifacts
rm -f artifacts/*.wasm artifacts/checksums.txt
for wasm in "$@"; do
    echo "Optimizing $(basename "$wasm")"
    # The VM rejects bulk-memory instructions emitted by newer Rust versions.
    # Lower them after optimization so subsequent passes cannot reintroduce them.
    wasm-opt -Os --enable-bulk-memory --llvm-memory-copy-fill-lowering \
        "$wasm" -o "artifacts/$(basename "$wasm")"
done

cosmwasm-check artifacts/*.wasm
(cd artifacts && sha256sum -- *.wasm > checksums.txt && cat checksums.txt)
