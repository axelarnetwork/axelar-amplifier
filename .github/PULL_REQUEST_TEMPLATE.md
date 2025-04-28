## Description

## Todos

- [ ] Unit tests
- [ ] Manual tests
- [ ] Documentation
- [ ] Connect epics/issues

## Convention Checklist
- [ ] Each contract should have a [client mod](https://github.com/axelarnetwork/axelar-amplifier/blob/27318df3e22e526867c91905d03a6a8b1a41110b/contracts/voting-verifier/src/client.rs) for others to interact with it.
- [ ] Derive macros
  - [EnsurePermissions](https://github.com/axelarnetwork/axelar-amplifier/blob/38321b74f9e3ce1516663b21067fc5a8391c53c2/packages/msgs-derive/src/lib.rs#L81): Contract permission control
  - [IntoContractError](https://github.com/axelarnetwork/axelar-amplifier/blob/eeb4406c7a0af04ec3afd8fcc39e65e6f2e69f7d/packages/axelar-wasm-std-derive/src/lib.rs#L12): Conversion from custom contract errors to [axelar_wasm_std::error::ContractError](https://github.com/axelarnetwork/axelar-amplifier/blob/eeb4406c7a0af04ec3afd8fcc39e65e6f2e69f7d/packages/axelar-wasm-std/src/error.rs#L16)
  - [IntoEvent](https://github.com/axelarnetwork/axelar-amplifier/blob/27318df3e22e526867c91905d03a6a8b1a41110b/packages/axelar-wasm-std-derive/src/lib.rs#L160): Event serialization
  - [migrate_from_version](https://github.com/axelarnetwork/axelar-amplifier/blob/27318df3e22e526867c91905d03a6a8b1a41110b/packages/axelar-wasm-std-derive/src/lib.rs#L349): Contract version management in the migrate function
- [ ] The state mod and msg mod should use separate data structures so that internal state changes do not break the contract interface. Check out the [interchain-token-service](https://github.com/axelarnetwork/axelar-amplifier/blob/27318df3e22e526867c91905d03a6a8b1a41110b/contracts/interchain-token-service/src/contract.rs) for reference.
  - msg.rs should never use any type from the state.rs
  - Shared types must be defined in a separate `shared` mod. If those types have already been defined somewhere else, then they should get re-exported in the `shared` mod


## Steps to Test

## Expected Behaviour

## Notes
