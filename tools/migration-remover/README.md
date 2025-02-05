# Migration Remover Tool

This tool cleans up a contract's `migrations` module and resets its content using the `template.rs` file.

The substring `#[migrate_from_version("0.0")]` in the template is automatically replaced with the current `major.minor` version from the contract's `Cargo.toml` file.

For best results, all migration-related code (e.g. `migrate` entry-point, `MigrateMsg`) should be inside the `migrations` module and the entry point re-exported in the contract's module using `pub use migrations::migrate;`

### Usage

```bash
cargo run --bin migration-remover -- -c <CONTRACT>
```

### Example

```bash
cargo run --bin migration-remover -- -c axelarnet-gateway
```
