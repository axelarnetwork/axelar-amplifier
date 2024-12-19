# Changelog

## [Unreleased](https://github.com/axelarnetwork/axelar-amplifier/tree/HEAD)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.3.0..HEAD)

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

