# Migration Remover Tool

This tool cleans up a contract's `migrations` module and resets its content using the `template.rs` file.

The substring `#[migrate_from_version("0.0")]` in the template is automatically replaced with the current `major.minor` version from the contract's `Cargo.toml` file.

### Usage

```bash
cargo run --bin migration-remover -- -c <CONTRACT>
```

### Example

```bash
cargo run --bin migration-remover -- -c axelarnet-gateway
```
