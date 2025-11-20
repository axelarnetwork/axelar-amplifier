
# Changelog

## [Unreleased](https://github.com/axelarnetwork/axelar-amplifier/tree/HEAD)

### Changed

- add `UpdateSigningParameters` execute message to allow governance to update block expiry [#1092](https://github.com/axelarnetwork/axelar-amplifier/pull/1092)
- add `SigningParameters` query to retrieve current signing parameters (block expiry) [#1092](https://github.com/axelarnetwork/axelar-amplifier/pull/1092)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/multisig-v2.3.2..HEAD)

## [v2.3.2](https://github.com/axelarnetwork/axelar-amplifier/tree/multisig-v2.3.2)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/multisig-v2.3.1..multisig-v2.3.2)

- update solana handler to parse events via CPI [#1048](https://github.com/axelarnetwork/axelar-amplifier/pull/1048)

## [v2.3.1](https://github.com/axelarnetwork/axelar-amplifier/tree/multisig-v2.3.1)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/multisig-v2.3.0..multisig-v2.3.1)

- remove duplicate prover chain mappings for multisig migration [#1053](https://github.com/axelarnetwork/axelar-amplifier/pull/1053)
- use full path for return macro types [#1050](https://github.com/axelarnetwork/axelar-amplifier/pull/1050)

## [v2.3.0](https://github.com/axelarnetwork/axelar-amplifier/tree/multisig-v2.3.0)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/multisig-v2.2.0..multisig-v2.3.0)

- coordinator v2 migration to add missing chains [#1011](https://github.com/axelarnetwork/axelar-amplifier/pull/1011)
- generate goldie tests for `Permissions` macro [#1001](https://github.com/axelarnetwork/axelar-amplifier/pull/1001)
- permissions check returns bool instead of address [#1005](https://github.com/axelarnetwork/axelar-amplifier/pull/1005)
- miscellaneous changes to add `router_api` macros to tests [#1004](https://github.com/axelarnetwork/axelar-amplifier/pull/1004)
- use `cosmos_addr!` macro instead of string literal conversion [#991](https://github.com/axelarnetwork/axelar-amplifier/pull/991)
- use `chain_name!` macro instead of string literal conversion [#992](https://github.com/axelarnetwork/axelar-amplifier/pull/992)

## [v2.2.0](https://github.com/axelarnetwork/axelar-amplifier/tree/multisig-v2.2.0)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/multisig-v2.1.0..multisig-v2.2.0)

- minor multisig update to version 2.2.0 [#977](https://github.com/axelarnetwork/axelar-amplifier/pull/977)
- remove `cosmwasm::Addr` type from `multisig` [#971](https://github.com/axelarnetwork/axelar-amplifier/pull/971)
- add migration endpoint for multisig contract [#966](https://github.com/axelarnetwork/axelar-amplifier/pull/966)
- coordinator can authorize callers with multisig [#953](https://github.com/axelarnetwork/axelar-amplifier/pull/953)
- add unit tests for multisig client [#955](https://github.com/axelarnetwork/axelar-amplifier/pull/955)
- use client package for all clients [#962](https://github.com/axelarnetwork/axelar-amplifier/pull/962)
- ensure permissions can accept empty direct attribute [#940](https://github.com/axelarnetwork/axelar-amplifier/pull/940)
- rename ensure permissions macro [#925](https://github.com/axelarnetwork/axelar-amplifier/pull/925)

## [v2.1.0](https://github.com/axelarnetwork/axelar-amplifier/tree/multisig-v2.1.0)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/multisig-v2.0.0..multisig-v2.1.0)

- accept arbitrary length message for signing [#839](https://github.com/axelarnetwork/axelar-amplifier/pull/839)

## [v2.0.0](https://github.com/axelarnetwork/axelar-amplifier/tree/multisig-v2.0.0) (2025-05-09)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/multisig-v1.2.1..multisig-v2.0.0)

- Change custom signature verification callback to use an execute message instead of a query [#833](https://github.com/axelarnetwork/axelar-amplifier/pull/833)

Note: version 2.0 is backwards compatible with version 1.x if not using a custom signature verification callback
