# Axelar Amplifier Integration Guide

This document provides an overview of the contracts on Axelar Amplifier protocol and outlines the steps required to integrate a chain. The document only covers the Amplifier contracts; a comprehensive list on other required components for the integration of a chain into Amplifier can be found in the [Axelar Amplifier Public Docs](https://docs.axelar.dev/dev/amplifier/chain-integration/introduction/).

---

## Amplifier Contracts Overview

To connect your chain to the Axelar network via the Interchain Amplifier, you will need to deploy or configure the following three contracts on Amplifier, and the configuration of `ampd`, as outlined below:

### Chain-Specific Amplifier Contracts

**Gateway**  

A contract on Amplifier that will forward incoming messages to the chain's correspoding verifier contract to check the validity of a transaction and forwards verified transactions onto the Amplifier router. It also receives messages from other chains to be processed by the multisig prover.
Most integrators will begin by using or customizing [this](../contracts/gateway/) Gateway Contract.

[Gateway Documentation](../contracts/gateway.md)

**Verifier**  

A contract on Amplifier protocol that verifies the validity of transactions on your chain. Most integrators will begin by using or customizing a Voting Verifier (such as [this](../contracts/voting-verifier/) one) or can be customized to your needs for cases such as verification via ZK Proof.

A Voting Verifier must be supported by a Verifier Set that will need to support the chain and vote on the truth of source chain transactions. 

[Voting Verifier Documentation](../contracts/voting_verifier.md)

**Prover**  

The prover contract is responsible for transforming gateway messages into a payload that is ready to be sent to the destination gateway. Most integrators will begin by using or customizing a multisig prover, such as [this](../contracts/multisig-prover/) one.

[Multisig Prover Documentation](../contracts/multisig_prover.md)


### ampd

Ampd is the off chain daemon that listens to the Axelar blockchain for specific events, connects to external blockchains via JSON-RPC, and uses [tofnd](https://github.com/axelarnetwork/tofnd) for signing transactions and batches of messages


### Infrastructure Contracts

These core contracts manage essential infrastructure logic for the protocol and typically do not require modification. If your chain does require the modificaiton of any of these contracts, please either file a Github issue or create a pull request with the requested changes to accommodate your chain. 

There is only one instance of each of these contracts in the protocol; any changes to these contracts must go through an upgrade of the contracts that via Axelar governance.

A description of each infrastructure contract can be found as follows:
* [Coordinator](../contracts/coordinator.md)
* [Multisig](../contracts/multisig.md)
* [Rewards](../contracts/rewards.md)
* [Router](../contracts/router.md)
* [Service Registry](../contracts/service_registry.md)

## Integration Steps

### 1. Deploy and instantiate the chain-specific contracts

The very first step is to deploy and instantiate the chain-specific contracts. This repository has reference contracts for each: [**Gateway**](../../../contracts/gateway), [**Voting Verifier**](../../../contracts/voting-verifier), and [**Multisig Prover**](../../../contracts/multisig-prover), and these reference contracts have been used in many of the initial chains live on Amplifier today. 

However, it is up to the integrator to determine how to best utilize the reference contracts, whether that may be by using the reference contracts we expose as is, maintaining a fork, or something else. It is important to note that these reference contracts are under active development and may change at any time, so integrators should be aware of the specific implementation and version of any reference contracts should they decide to use them.

### 2. Configure `ampd`

If your chain is **not EVM-compatible**, you will need to implement an **ampd** module that Amplifier can use to communicate with your chain. Using the [ampd EVM module](../../../ampd/src/evm) as a design template. 

NOTE: any modifications you make to `ampd` to support your chain will need to be upstreamed and merged back into the main repository.

If your chain is **EVM-compatible**, you can use the existing **ampd** module for EVM chains: [ampd EVM module](../../../ampd/src/evm), and there is nothing to do from your side.

### 3. Configure a verifier set

The chain must be supported by a verifier set. Testnet and mainnet will have an initial set of ~30 verifiers globally that can support your chain. 

### 4. Fund rewards pools

Create rewards pools for your verifier and multisig prover contracts. These rewards pools incentivize verifiers to support your chain. Please refer to the [rewards contract](../contracts/rewards/src/) for more info.

## Testing and Deployment

Once your contracts are deployed, you can test them, along with the external smart contracts deployed to your chain, on the public devnet. Please refer to the public [developer documentation](https://docs.axelar.dev/dev/amplifier/chain-integration/integrate-a-chain/) for the latest information on the public devnet and example deployment scripts to get you started. 