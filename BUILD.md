# Amplifier Build Instructions

This document provides instructions for building Amplifier components, including contracts and the `ampd` service.

## Prerequisites

- Rust and Cargo (check the current rust version in the `workspace.package` of root [Cargo.toml](Cargo.toml) file)
- Docker (for reproducible optimized contract builds)
- [just](https://crates.io/crates/just) cargo crate (for running the optimizer and other useful project specific commands)

## Building the Project

### Building Everything for Development

To build the entire project for development and testing:

```bash
cargo build
```

This will compile all packages, contracts, and the ampd service for your local machine architecture.

### Building Specific Components for Development

To build a specific component for development/testing purposes:

```bash
cd contracts/<contract-name>
cargo build
```
Or run tests:
```bash
cd contracts/<contract-name>
cargo test
```

## Release Build

CosmWasm contracts need to be built for the WebAssembly target and optimized for deployment. The optimization process is essential for reducing contract size and gas costs.

Install the [just](https://crates.io/crates/just) cargo crate

```bash
cargo install just
```

To create a reproducible wasm build for a contract via the cosmwasm [optimizer](https://github.com/CosmWasm/optimizer):

```bash
just optimize
```

This command:
- Compiles the contract for the WebAssembly target with appropriate flags
- Runs the resulting Wasm file through an optimizer
- Produces a deployment-ready binary

Make sure Docker is running on your system before executing this command.

Note: For actual blockchain deployment, always use the optimized contract, not the standard build output.

## ampd

### Configuration

To run a local instance of `ampd`, you need to provide a configuration file. You can use [this template](ampd/src/tests/config_template.toml) as a starting point:

```bash
# Copy the config template
cp ampd/src/tests/config_template.toml my_ampd_config.toml

# Edit the configuration as needed
```

Customize the configuration according to your requirements (network connections, RPC endpoints, etc.).

### Build
```bash
cargo build --bin ampd
```

### Run
```bash
./target/debug/ampd --config my_ampd_config.toml
```

## Troubleshooting

### Git Submodule Issues

If you encounter errors related to missing protocol buffer files or other submodule content, ensure that you've correctly initialized and updated submodules:

```bash
git submodule init
git submodule update
```

### Docker Issues with Contract Optimization

When running contract optimization, make sure that:
- Docker is installed and running
- You have sufficient permissions to run Docker commands
- Your Docker daemon has access to the internet to pull the optimizer image
