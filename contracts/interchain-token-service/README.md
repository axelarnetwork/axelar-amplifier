# Interchain Token Service Hub

## Overview

The Interchain Token Service (ITS) Hub contract is a crucial component of a cross-chain ITS protocol. It facilitates the transfer of tokens between different blockchains, manages token deployments, and tracks the token supply across chains. It connects to ITS edge contracts on different chains (e.g. EVM ITS [contract](https://github.com/axelarnetwork/interchain-token-service)).

## Key Components

1. **ITS Message Processing**: Processes incoming ITS messages from trusted sources.
2. **Token Supply Tracking**: Ensures accurate token supply is maintained during cross-chain operations.
3. **ITS Address Registry**: Tracks the trusted ITS address for each chain for routing. This avoids each chain's ITS contract from having to know about all other ITS contract addresses.

## Cross-chain messaging

The ITS Hub makes use of the Axelarnet gateway [contract](../contracts/axelarnet-gateway/) to facilitate sending or receiving cross-chain messages. Messages are sent via `CallContract`, and received when the Axelarnet gateway is executed (by a relayer / user) through `Execute`, which in turn executes ITS Hub's `Execute` method.

## Token Supply Invariant

ITS Hub maintains the token supply for native interchain tokens for every chain they're deployed to. This helps isolate the security risk between chains. A compromised chain can only affect the total token supply that was sent to that chain in the worst case. For e.g. if USDC was deployed from Ethereum to Solana via the ITS Hub, and 10M USDC was moved to Solana (in total). If there's a compromise on Solana (potentially the chain itself, or the Solana ITS contract, or another related contract), an attacker can only withdraw at most 10M USDC back to Ethereum or another chain (and not all the bridged USDC locked on the Ethereum ITS contract). ITS Hub will prevent all USDC transfers from Solana once 10M USDC has been moved back out from it.
