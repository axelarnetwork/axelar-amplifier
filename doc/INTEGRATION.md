# Axelar Amplifier Integration Guide

This document provides an overview of the contracts on Axelar Amplifier protocol and outlines the steps required to integrate a chain. The document only covers the Amplifier contracts; a comprehensive list on other required components for the integration of a chain into Amplifier can be found in the [Axelar Amplifier Public Docs](https://docs.axelar.dev/dev/amplifier/chain-integration/introduction/).

---

## Amplifier Contracts Overview

To connect your chain to the Axelar network via the Interchain Amplifier, you will need to deploy or configure the following three contracts on Amplifier, and the configuration of `ampd`, as outlined below:

### Chain-Specific Amplifier Contracts

**Gateway**  

A contract on Amplifier that will forward incoming messages to the chain's correspoding verifier contract to check the validity of a transaction and forwards verified transactions onto the Amplifier router. It also receives messages from other chains to be processed by the multisig prover.
Most integrators will begin by using or customizing this Gateway Contract.
[Gateway Documentation](../doc/src/contracts/gateway.md)

**Voting Verifier**  

A contract on Amplifier protocol that verifies the validity of transactions on your chain. Most integrators will begin by using or customizing a Voting Verifier or can be customized to your needs for cases such as verification via ZK Proof.

A Voting Verifier must be supported by a Verifier Set will need to support the chain and vote on the truth of source chain transactions. 

[Voting Verifier Documentation](../doc/src/contracts/voting_verifier.md)

**Multisig Prover**  

The prover contract is responsible for transforming gateway messages into a payload that is ready to be sent to the destination gateway.

[Multisig Prover Documentation](../doc/src/contracts/multisig_prover.md)


### ampd

Ampd is the off chain daemon responsible for voting and signing within the amplifier protocol. The daemon listens to the Axelar blockchain for specific events, connects to external blockchains via JSON-RPC, and uses [tofnd](https://github.com/axelarnetwork/tofnd) for signing transactions and batches of messages


### Infrastructure Contracts

These core contracts manage essential infrastructure logic for the protocol and typically do not require modification. If your chain does require the modificaiton of any of these contracts, please let us know by filing a Github issue to this repository to create a pull request to be merged. 

**Coordinator**  

Manages coordination between contracts in the Amplifier system. [Coordinator Documentation](../doc/src/contracts/coordinator.md)

**Multisig**  

Facilitates verifier signing sessions that is leveraged by the multisig prover contract. The Multisig contract currently supports ECDSA and ED25519 signature schemes. [Multisig Documentation](../doc/src/contracts/multisig.md)

**Rewards**  

Manages verifier rewards. [Rewards Documentation](../doc/src/contracts/rewards.md)

**Router**  

Routes messages between gateway contracts connected in the Amplifier ecosystem, and responsible for performing various administrative functions for chain. [Router Documentation](../doc/src/contracts/router.md)

**Service Registry**  

Registers and tracks the pool of verifiers that support each and every Amplifier chain. [Service Registry Documentation](../doc/src/contracts/service_registry.md)

## Integration Steps

### 1. Deploy and instantiate the chain-specific contracts

The very first step is to deploy and instantiate the chain-specific contracts. This repository has reference contracts for each: [**Gateway**](../contracts/gateway), [**Voting Verifier**](../contracts/voting-verifier), and [**Multisig Prover**](../contracts/multisig-prover), and these reference contracts have been used in many of the initial chains live on Amplifier today. 

However, it is up to the integrator to determine how to best utilize the reference contracts, whether that may be by using the reference contracts we expose as is, maintaining a fork, or something else. It is important to note that these reference contracts are under active development and may change at any time, so integrators should be aware of the specific implementation and version of any reference contracts should they decide to use them.

### 2. Configure `ampd`

If your chain is **not EVM-compatible**, you will need to implement an **ampd** module that Amplifier can use to communicate with your chain. Using the [ampd EVM module](../ampd/src/evm) as a design template, you will have to fork this repository and create a pull request to merge into the main repository.

If your chain is **EVM-compatible**, you can use the existing **ampd** module for EVM chains: [ampd EVM module](../ampd/src/evm), and there is nothing to do from your side.

### 3. Configure a verifier set

If your verifier contract is a voting verifier, the chain must be supported by a verifier set. Testnet/mainnet has a global set of ~30 verifiers that will need to support your chain. 

To facilitate verifier onboarding to support your chain, please follow the guide laid out in [this page - link TBD]().

### 4. Fund rewards pools

Create rewards pools for your verifier and multisig prover contracts. These rewards pools incentivize verifiers to support your chain. Instructions on how to create and fund rewards pools can be found [here](https://docs.axelar.dev/dev/amplifier/add-rewards).

## Testing

## Deployment
