# Amplifier Build Instructions

This document provides instructions for building Amplifier components, including contracts and the `ampd` service.

## Prerequisites

- Rust and Cargo (rust-version = "1.81.0" currently required)
- Docker (for contract optimization)
- Git (for cloning and handling submodules)
- cargo-run-script (for running optimization scripts)

## Initial Setup

When cloning the repository, make sure to initialize and update submodules:

```bash
# Clone the repository
git clone https://github.com/axelarnetwork/axelar-amplifier.git
cd axelar-amplifier

# Initialize and update submodules
git submodule init
git submodule update
```

If you've already cloned the repository without initializing submodules and encounter errors like:

```
Error: Custom { kind: Other, error: "protoc failed: Could not make proto path relative: proto-files/ampd/v1/ampd.proto: No such file or directory" }
```

Run the submodule initialization commands as shown above.

## Building the Project

### Building Everything

To build the entire project:

```bash
cargo build
```

This will compile all packages, contracts, and the `ampd` service.

### Building Specific Components

To build a specific contract or component:

```bash
# Example: Build the coordinator contract
cd contracts/coordinator
cargo build
```

## Optimizing Contracts

CosmWasm contracts need to be optimized for deployment. The contracts in this repository include optimization scripts in their Cargo.toml files.

### Installing cargo-run-script

First, install the cargo-run-script tool:

```bash
cargo install cargo-run-script
```

### Running Contract Optimization

Navigate to the contract directory and run the optimization script:

```bash
# Example: Optimize the coordinator contract
cd contracts/coordinator
cargo run-script optimize
```

This will execute a Docker command (defined in the contract's Cargo.toml) that:
- Mounts your current directory to a Docker container
- Uses volume mounts for caching compilation artifacts
- Produces an optimized WebAssembly binary

The typical optimize script looks like:

```
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/optimizer:0.16.1
```

Make sure Docker is running on your system before executing this command.

## Running ampd

### Configuration

To run a local instance of `ampd`, you need to provide a configuration file. You can use the template located at `ampd/src/tests/config_template.toml` as a starting point:

```bash
# Copy the config template
cp ampd/src/tests/config_template.toml my_ampd_config.toml

# Edit the configuration as needed
```

Customize the configuration according to your requirements (network connections, RPC endpoints, etc.).

### Building and Running ampd

```bash
# Build ampd
cargo build --bin ampd

# Run ampd with your configuration
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

## Advanced: Release Process

For team members responsible for managing releases, please refer to the `ampd/ampd-release.md` document for detailed instructions on the release process.
