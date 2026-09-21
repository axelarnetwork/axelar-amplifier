#!/bin/sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_dir"

# CI builds/loads this tag with Buildx; `just optimize` builds it locally first.
image=${OPTIMIZER_IMAGE:-axelar-amplifier-optimizer:local}
cache_prefix=${OPTIMIZER_CACHE_PREFIX:-axelar_amplifier_optimizer}
exec docker run --rm --platform linux/amd64 \
    -v "$repo_dir:/code" \
    --mount "type=volume,source=${cache_prefix}_rust198_binaryen132_target,target=/target" \
    --mount "type=volume,source=${cache_prefix}_registry,target=/usr/local/cargo/registry" \
    --mount "type=volume,source=${cache_prefix}_git,target=/usr/local/cargo/git" \
    "$image" "$@"
