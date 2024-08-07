# Interchain Token Service Hub

## Overview

The Interchain Token Service (ITS) Hub contract is a crucial component of a cross-chain ITS protocol. It facilitates the transfer of tokens between different blockchains, manages token deployments, and maintains balance integrity across chains. It connects to ITS edge contracts on different chains (e.g. EVM ITS [contract](https://github.com/axelarnetwork/interchain-token-service)).

## Key Components

1. **ITS Message Processing**: Processes incoming ITS messages from trusted sources.
2. **Balance Tracking**: Ensures accurate token balances are maintained during cross-chain operations.
3. **ITS Address Registry**: Tracks the trusted ITS address for each chain for routing.

### Cross-chain messaging

The ITS Hub makes use of the Axelarnet gateway [contract](../contracts/axelarnet-gateway/) to facilitate sending or receiving cross-chain messages. Messages are sent via `CallContract`, and received when the Axelarnet gateway is executed (by a relayer / user) through `Execute`, which in turn executes ITS Hub's `Execute` method.
