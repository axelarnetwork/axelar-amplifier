# Axelar Amplifier Code Review Conventions

## Contracts (applies to contracts/**)

If any changed file is under `contracts/`, verify the following conventions:

- Each contract must have a client mod for others to interact with it
- Derive macros must be used where applicable:
  - `Permissions` for contract permission control
  - `IntoContractError` for conversion from custom errors to `axelar_wasm_std::error::ContractError`
  - `IntoEvent` for event serialization
  - `migrate_from_version` for contract version management in the migrate function
- The `state` mod and `msg` mod must use separate data structures (internal state changes must not break the contract interface)
  - `msg.rs` must never use any type from `state.rs`
  - Shared types must be defined in a separate `shared` mod. If those types exist elsewhere, they should be re-exported in the `shared` mod

## ampd (applies to ampd/**)

<!-- TODO: Add ampd-specific conventions -->

## ampd-handlers (applies to ampd-handlers/**)

<!-- TODO: Add ampd-handlers-specific conventions -->
