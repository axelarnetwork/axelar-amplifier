# Changelog

## [Unreleased](https://github.com/axelarnetwork/axelar-amplifier/tree/HEAD)

- Move the XRPL multisig prover contract into this repository from [axelar-amplifier-xrpl](https://github.com/axelarnetwork/axelar-amplifier-xrpl) and build it against the workspace's current `axelar-wasm-std`, `router-api`, `multisig`, `coordinator`, `service-registry`, ITS and `msgs-derive` crates. Messages, queries, events and storage are unchanged.
- Pass this contract as the signing session's `sig_verifier`, as before: XRPL signatures are over a per-signer digest, so the multisig contract delegates their verification here. Requires the `multisig` crate with the callback restored (see the multisig changelog).

## [v1.4.3](https://github.com/axelarnetwork/axelar-amplifier-xrpl/tree/xrpl-multisig-prover-v1.4.3)

Last release from the previous repository. Earlier history: [axelar-amplifier-xrpl CHANGELOG](https://github.com/axelarnetwork/axelar-amplifier-xrpl/blob/xrpl/CHANGELOG.md).
