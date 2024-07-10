# Axelar Amplifier

The Interchain Amplifier enables developers to permissionlessly set up connections to the Axelar network. Developers
gain access to Axelar's interconnected network of chains and can "amplify" their resources by paying the cost equivalent
to developing only one connection. They can establish connections between new ecosystems or existing chains to add new
network properties, such as improved security or better delivery and availability.

### Documentation

High level documentation and diagrams can be found in the [doc](doc/README.md) directory.

### Contract Json Schemas

Json schemas for types used in the contract apis can be generated by navigating to the `./contracts/{contract_name}`
directory and running `cargo schema`. This will generate a `./contracts/{contract_name}/schema` directory containing the
json schemas for types used to instantiate, execute, query etc.

### Development and Testing

When developing contracts to integrate with amplifier, the `cw-multi-test` crate can be used to create a simulated
blockchain environment, where different contracts can be deployed and interacted with, and contracts can interact with
each other. See the [integration-tests](integration-tests) package for examples, as well as reusable helper functions.

### Versioning

The semver for new releases is calculated automatically based on the commit messages and the folders where changes were
made. The configuration for each piece of software released (e.g. ampd, gateway...) can be seen in the release.yaml
file. You can perform a dry-run using the release action to be sure that the next version is what you intend it to be.
The basic rules are as follows:

- a commit with a message that does not include any associated tag (e.g. major-contracts) for release will be considered
  a patch release
- a commit with a message with minor tag e.g. `feat(minor-ampd):...` will be considered a minor release, and the same
  logic applies to major releases
- if no changes are detected in the watched directories, the release will not bump the version. For example, if since
  last release for the gateway contract no changes were made in the `contracts/gateway` or `packages/` directory. A new
  release will not bump the version.

### Compatibility

For the amplifier preview with version numbers < 1.0.0, please refer to the following compatibility table to select versions of 
contracts and `ampd` that work well together.

| Binary      | Version |
|-------------|---------|
| ampd              | 0.5.0 |
| coordinator       | 0.2.0 |
| gateway           | 0.2.3 |
| multisig-prover   | 0.6.0 |
| multisig          | 0.4.1 |
| nexus-gateway     | 0.3.0 |
| rewards           | 0.4.0 |
| router            | 0.3.3 |
| service-registry  | 0.4.1 |
| voting-verifier   | 0.5.0 |
| [tofnd](https://github.com/axelarnetwork/tofnd) | TBD |
| [solidity-contracts](https://github.com/axelarnetwork/axelar-gmp-sdk-solidity) | 5.9.0 |
