# Amplifier Build Instructions

This document provides instructions for building Amplifier components, including contracts and the `ampd` service.

## Prerequisites

- Rust and Cargo (rust-version = "1.81.0" currently required)
- Docker (for contract optimization)
- Git (for cloning and handling submodules)
- cargo-run-script (for running optimization scripts)

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

## Building and Optimizing Contracts for Deployment

CosmWasm contracts need to be built for the WebAssembly target and optimized for deployment. The optimization process is essential for reducing contract size and gas costs.

### Installing cargo-run-script

First, install the cargo-run-script tool:

```bash
cargo install cargo-run-script
```

### Building and Optimizing a Contract for Deployment

To create a reproducible wasm build for a contract via the cosmwasm [optimizer](https://github.com/CosmWasm/optimizer):

```bash
cd contracts/<contract-name>
cargo run-script optimize
```

This command:
- Compiles the contract for the WebAssembly target with appropriate flags
- Runs the resulting Wasm file through an optimizer
- Produces a deployment-ready binary

Make sure Docker is running on your system before executing this command.

Note: For actual blockchain deployment, always use the optimized contract, not the standard build output.

## ampd

### Configuration

To run a local instance of `ampd`, you need to provide a configuration file. You can use the template located at `ampd/src/tests/config_template.toml` as a starting point:

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
