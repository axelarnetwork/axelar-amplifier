# Changelog

## [Unreleased](https://github.com/axelarnetwork/axelar-amplifier/tree/HEAD)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.2.0..HEAD)

- Change event index in message ids from u32 to u64. Emit message id from voting verifier

#### Migration Notes

The voting verifier contracts must be migrated before ampd is upgraded.