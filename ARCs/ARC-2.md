# ARC-2: ITS Hub Register Existing ITS Tokens

## Metadata

- **ARC ID**: 2
- **Author(s)**: CJ Cobb
- **Status**: Draft
- **Created**: 2024-12-3
- **Last Updated**: 2024-12-3
- **Target Implementation**: Q4 2024

## Summary

Add an admin/governance method on the ITS hub that allows registering a token that has already been deployed
in p2p mode (without the hub). This allows existing ITS tokens that were deployed prior to the ITS hub release to 
be registered with the hub and to be processed through the hub. At the edge contracts, these tokens will need to be
migrated from p2p mode to hub mode.

## Motivation

### Background

The ITS Hub tracks every deployed token, including the chains the token was deployed to, and will reject transfers
of tokens to chains for which no deployment occurred. For example, if a token was deployed to chain A and B, a 
transfer of that token from B to C will be rejected. However, tokens that were deployed prior to the launch of the
ITS hub were deployed in p2p mode, and the ITS hub is not aware of those deployments. If one of those tokens is 
then deployed to a hub connected chain, the ITS hub has an incomplete view of which chains the token is deployed 
on, and will reject transfers that should succeed. For example, imagine token T is deployed on A and B in p2p 
mode. The hub is not aware of either of these deployments. Then, token T is deployed from A to C via the hub. Now 
the hub knows about the token T deployment on A and C, but not B. A transfer from C to B will then fail, even 
though the token is deployed on B and thus the transfer should succeed.


### Goals

- Allow a token to be transferred to all chains where it is deployed
- Maintain balance tracking and other invariants even when a token was not deployed via the hub

## Design

The ITS hub will expose an admin/governance method to register an existing token with the hub:

```rust

pub enum ExecuteMsg {
    // all of the existing methods remain unchanged

    #[permission(Elevated)]
    RegisterToken {
        deployed_chain: ChainNameRaw,
        origin_chain: ChainNameRaw,
        token_id: TokenId,
        decimals: u8,
        supply: Option<Uint256>, // None if not tracked for this chain
        deployment_type: TokenDeploymentType // Trustless or Custom
    }
}
```

The above command will register the token and store all of the neccessary information. The supply is used to
initialize balance tracking. The supply can be hard to specify with exact correctness, due to inflight transfers.
Therefore, the command can be executed more than once with the same arguments albeit a different supply, which will
overwrite the existing supply for that chain.

The command will fail if the token instance already exists with a different decimals, origin_chain or
deployment_type (or maybe we shouldn't fail, in case there is a mistake and we need to overwrite?).
The command will fail if the supply is set to None and deployed_chain does not equal origin chain.
The command will fail if either the deployed_chain or origin_chain is not registered with the hub.

## Risks

- For this to work effectively, there is operational overhead of determing every ITS token, and registering each
with the ITS hub correctly. There is a possibility some are missed, or registered incorrectly, and thus need to be adjusted.

### Changelog

| Date | Revision | Author | Description |
|------|-----------|---------|-------------|
| 2024-12-3 | v1.0 | CJ Cobb | Initial ARC draft |