# Changelog

## [Unreleased](https://github.com/axelarnetwork/axelar-amplifier/tree/HEAD)

- Move the XRPL gateway contract into this repository from [axelar-amplifier-xrpl](https://github.com/axelarnetwork/axelar-amplifier-xrpl) and build it against the workspace's current `axelar-wasm-std`, `router-api`, `multisig`, `coordinator`, `service-registry`, ITS and `msgs-derive` crates. Messages, queries, events and storage are unchanged.
- Gate `migrate` with `migrate_from_version("1.3")` so only the deployed minor version can be upgraded, and stop re-initialising the killswitch on migration.
- Generate the JSON schema from this contract's own messages instead of the generic gateway's.
- Report the fields of `PayloadHashMismatch` consistently for interchain transfers: `expected` is the hash in the message, `actual` the hash of the given payload.

## [v1.3.3](https://github.com/axelarnetwork/axelar-amplifier-xrpl/tree/xrpl-gateway-v1.3.3)

Last release from the previous repository. Earlier history: [axelar-amplifier-xrpl CHANGELOG](https://github.com/axelarnetwork/axelar-amplifier-xrpl/blob/xrpl/CHANGELOG.md).
