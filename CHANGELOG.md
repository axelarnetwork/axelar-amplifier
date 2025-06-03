# Changelog

## [Unreleased](https://github.com/axelarnetwork/axelar-amplifier/tree/HEAD)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.8.1..HEAD)

## [v1.8.1](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.8.1)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.8.0..ampd-v1.8.1)

- Add configurable delay before block processing [#860](https://github.com/axelarnetwork/axelar-amplifier/pull/860)
- Add curl and wget to ampd dockerfile [#887](https://github.com/axelarnetwork/axelar-amplifier/pull/887)
- Make gRPC related errors transparent [#870](https://github.com/axelarnetwork/axelar-amplifier/pull/870)

## [v1.8.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.8.0) (2025-05-16)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.7.0..ampd-v1.8.0)

- Change XRPL handler to listen to multisig contract [#850](https://github.com/axelarnetwork/axelar-amplifier/pull/850)

## [v1.7.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.7.0) (2025-04-07)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.6.0..ampd-v1.7.0)

- Add Solana support to ampd [#744](https://github.com/axelarnetwork/axelar-amplifier/pull/744)
- Fix parsing of non-standard XRPL currencies [#797](https://github.com/axelarnetwork/axelar-amplifier/pull/797)

## [v1.6.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.6.0) (2025-04-02)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.5.1..ampd-v1.6.0)

- Separate multisig config per chain [#772](https://github.com/axelarnetwork/axelar-amplifier/pull/772) and [#790](https://github.com/axelarnetwork/axelar-amplifier/pull/790)
- Refactor event sub to support gRPC subscribe [#777](https://github.com/axelarnetwork/axelar-amplifier/pull/777)
- Make chain names case insensitive in ampd verification [#785](https://github.com/axelarnetwork/axelar-amplifier/pull/785) and [#787](https://github.com/axelarnetwork/axelar-amplifier/pull/787)
- Use case sensitive destination chain in XRPL gateway and verifier [#788](https://github.com/axelarnetwork/axelar-amplifier/pull/788)
- Fix expected format for non-standard XRPL currencies [#789](https://github.com/axelarnetwork/axelar-amplifier/pull/789)

## [v1.5.1](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.5.1) (2025-03-26)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.5.0..ampd-v1.5.1)

- Fix arithmetic operations with XRPLTokenAmount [#780](https://github.com/axelarnetwork/axelar-amplifier/pull/780)

## [v1.5.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.5.0) (2025-03-24)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.4.0..ampd-v1.5.0)

- Add support for Starknet GMP [#731](https://github.com/axelarnetwork/axelar-amplifier/pull/731)
- Add support for XRPL GMP and token transfers [#764](https://github.com/axelarnetwork/axelar-amplifier/pull/764)
- Ignore fee estimation failures [#767](https://github.com/axelarnetwork/axelar-amplifier/pull/767)

## [v1.4.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.4.0) (2024-12-12)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.3.0..ampd-v1.4.0)

- Update sui dependencies to fix RPC issue [#721](https://github.com/axelarnetwork/axelar-amplifier/pull/721)
- Add support for Bech32m message id format [#689](https://github.com/axelarnetwork/axelar-amplifier/pull/689)
- Add Router migration to delete chains [#710](https://github.com/axelarnetwork/axelar-amplifier/pull/710)

## [v1.3.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.3.0) (2024-11-19)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.2.0..ampd-v1.3.0)

- Change event index in message ids from u32 to u64. Emit message id from voting verifier [#666](https://github.com/axelarnetwork/axelar-amplifier/pull/666)
- Ampd switch from horizon to RPC client for Stellar verifier [#694](https://github.com/axelarnetwork/axelar-amplifier/pull/694)

#### Migration Notes
Upgrade or deploy contracts/components in the below order:

##### Contracts that should be deployed fresh
- interchain-token-service
- axelarnet-gateway (deploy with chain name "axelar")

##### Contracts that need migration
- coordinator
- gateway
- rewards
- router
- multisig
- multisig-prover
- service-registry
- voting-verifier

##### Components that need upgrading
- ampd

##### Contracts no longer used (no longer part of the active system)
- nexus-gateway

The voting verifier contracts must be migrated before ampd is upgraded. Existing ampd instances will continue to work even after the contract migration, but we recommend upgrading ampd.

