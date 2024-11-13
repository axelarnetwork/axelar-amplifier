# ARC-1: ITS Hub Multi-Chain Token Linking

## Metadata

- **ARC ID**: 1
- **Author(s)**: Milap Sheth
- **Status**: Draft
- **Created**: 2024-11-14
- **Last Updated**: 2024-11-14
- **Target Implementation**: Q4 2024

## Summary

Extend the Interchain Token Service (ITS) Hub to support linking existing tokens across different chains, potentially using different decimals. This improvement enables token transfers for custom token links across both EVM and non-EVM chains by supporting appropriate decimal scaling.

## Motivation

### Background

The current ITS `DeployTokenManager` message type only supports linking existing tokens with identical decimals. This limitation is particularly problematic when dealing with non-EVM chains, which often cannot support the high decimal values (e.g., 18) common in EVM chains due to token amount type constraints.

### Goals

- Enable linking of existing tokens across connected chains
- Support linking tokens with different decimal precisions

## Detailed Design

### Overview

Two potential solutions are proposed to implement this enhancement:

1. Modify the existing `DeployTokenManager` message type
2. Introduce new message types for token registration and linking

### Technical Specification

#### Solution 1: Enhanced DeployTokenManager

```solidity
struct DeployTokenManager {
    bytes32 tokenId;
    uint256 tokenManagerType;
    bytes params;
    uint8 sourceDecimals;
    uint8 destinationDecimals;
}
```

ITS Hub can use the source and destination token decimals to determine the appropriate scaling factor to apply when intercepting this message. ITS edge contract can populate the source token decimals by reading the token metadata, however the destination token decimals will need to be provided by the deployer.

Setting this incorrectly however can be lead to the ITS hub recording the deployment incorrectly, while the deployment tx on the destination ITS will fail due to mismatching decimals, which isn’t recoverable.

One potential mitigation is to allow the deployer to resubmit the msg but with a different destination decimals, and have ITS hub overwrite the recorded deployment. ITS Hub can allow this overwrite until the first Transfer msg is encountered to allow the user to fix their deployment. This adds some more complexity in ITS hub setup.

Flow:

1. Deployer submits `DeployTokenManager`
2. ITS Hub calculates scaling factor and records deployment
3. Destination chain deploys token manager with the corresponding token address (extracted from the params)

#### Solution 2: Token Registration and Linking

Two new ITS message types are introduced: `RegisterToken` and `LinkToken`.

```solidity
struct RegisterToken {
    bytes tokenAddress;
    uint8 decimals;
}

struct LinkToken {
    bytes32 tokenId;
    uint256 tokenManagerType;
    bytes sourceToken;
    bytes destinationToken;
    bytes params;
}
```

New entrypoints in ITS Edge contract:

- `registerToken(address token)`
- `linkToken(bytes32 tokenId, uint256 tokenManagerType, bytes destinationToken, bytes params)`

Flow:

1. User calls `registerToken` on ITS Chain A to submit a `RegisterToken` msg type to ITS Hub to register token data in ITS hub.
2. ITS Hub processes the `RegisterToken` msg and stores the mapping of token address to decimals.
3. User does the same on ITS Chain B.
4. User calls `linkToken` on ITS Chain A with the destination token address for Chain B. This submits a `LinkToken` msg type to ITS Hub.
5. ITS Hub intercepts the `LinkToken` msg. It reads the decimals for each token address from it’s storage to calculate the scaling factor and creates the TokenInstance. If a token address isn’t registered in ITS Hub, it fails.
6. ITS Chain B receives the `LinkToken` msg. It deploys the corresponding token manager for the token to set it up.
7. ITS Hub can now receive Transfer msgs for this `tokenId`.

## Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|---------|------------|------------|
| Solution 1: Incorrect decimal configuration | High | Medium | ITS hub recovery mechanism |

## Risks

- Solution 1 is simpler to implement and thus rollout. But it is error prone and recovery in the event of an error is more complicated
- Solution 2 introduces an additional step, but is more robust against errors
- There is also the option to not support scaling altogether, but this reduces the power of ITS on non EVM chains with different token standards.

### References

- [InterchainTokenServiceTypes.sol](https://github.com/axelarnetwork/interchain-token-service/blob/main/contracts/types/InterchainTokenServiceTypes.sol)

### Changelog

| Date | Revision | Author | Description |
|------|-----------|---------|-------------|
| 2024-11-14 | v1.0 | Milap Sheth | Initial ARC draft |
