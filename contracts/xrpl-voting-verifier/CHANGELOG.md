# Changelog

## [Unreleased](https://github.com/axelarnetwork/axelar-amplifier/tree/HEAD)

- Move the XRPL voting verifier contract into this repository from [axelar-amplifier-xrpl](https://github.com/axelarnetwork/axelar-amplifier-xrpl) and build it against the workspace's current `axelar-wasm-std`, `router-api`, `multisig`, `coordinator`, `service-registry`, ITS and `msgs-derive` crates. Messages, queries, events and storage are unchanged.
- Gate `migrate` with `migrate_from_version("2.0")` so only the deployed minor version can be upgraded, and stop re-initialising the killswitch on migration.
- Drop the unused `multisig` dependency.

## [v2.0.0](https://github.com/axelarnetwork/axelar-amplifier-xrpl/tree/xrpl-voting-verifier-v2.0.0)

Last release from the previous repository. Earlier history: [axelar-amplifier-xrpl CHANGELOG](https://github.com/axelarnetwork/axelar-amplifier-xrpl/blob/xrpl/CHANGELOG.md).
