
# Changelog

## [Unreleased](https://github.com/axelarnetwork/axelar-amplifier/tree/HEAD)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/multisig-v2.2.0..HEAD)

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
