# Pull Request: Remove Remote Minter from ITS Portal Deployments

## Summary
This PR updates the ITS portal to use the new `deployRemoteInterchainToken` method introduced in ITS v2.1.0 and removes the default behavior of setting a minter on remote token deployments.

## Changes Made

### File: `apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts`
- Changed from `deployRemoteInterchainToken2` to `deployRemoteInterchainToken`
- Removed the `minter` parameter from remote deployment calls
- The minter is now only set on the source chain deployment, not on remote chains

## Background
As discussed in the Slack thread:
- The deprecated `deployRemoteInterchainToken2` method is being removed in the upcoming ITS release
- Setting a minter on remote deployments has security implications and complexity with cross-chain addresses
- The new method provides a cleaner API for the standard use case

## Impact
- **Breaking Change**: No, this maintains backward compatibility
- **Security**: Improved - removes potential security issues with cross-chain minter addresses
- **ITS Hub**: Better alignment with ITS hub accounting checks

## Testing Recommendations
1. Deploy a new interchain token through the portal
2. Verify the token is deployed correctly on the source chain with the specified minter
3. Verify remote deployments do not have a minter set
4. Test deployment to non-EVM chains (e.g., Sui) to ensure address format compatibility

## Related Links
- [ITS v2.1.0 Release](https://github.com/axelarnetwork/interchain-token-service/blob/v2.1.0/contracts/interfaces/IInterchainTokenFactory.sol#L122)
- [New deployRemoteInterchainToken method](https://github.com/axelarnetwork/interchain-token-service/blob/v2.1.0/contracts/interfaces/IInterchainTokenFactory.sol#L122)
- [Advanced method with minter support](https://github.com/axelarnetwork/interchain-token-service/blob/v2.1.0/contracts/interfaces/IInterchainTokenFactory.sol#L139)