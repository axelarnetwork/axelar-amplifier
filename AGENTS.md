# CosmWasm contracts

When changing CosmWasm contracts or their message types:

- Derive `Permissions` for each contract's `ExecuteMsg` and declare permissions explicitly for every variant, including unrestricted ones. Message types used only to call external contracts are exempt.
- In each `execute` entry point, call `msg.ensure_permissions(...)` and propagate failures before dispatching the message or performing state changes. Do not discard the result or allow an execution path to bypass the check.
- Use unvalidated strings for incoming account addresses in `InstantiateMsg`, `ExecuteMsg`, `QueryMsg`, and `MigrateMsg`, including nested types, rather than `cosmwasm_std::Addr`. Validate local addresses with `deps.api.addr_validate(...)` before treating them as `Addr`; deserialization does not validate them. Use the appropriate chain-specific validation for external-chain addresses.
