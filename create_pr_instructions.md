# Instructions to Create PR for ITS Portal Update

## Quick Setup

1. Fork the repository at https://github.com/axelarnetwork/axelarjs
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/axelarjs.git
   cd axelarjs
   ```

3. Create the branch and apply the patch:
   ```bash
   git checkout -b fix/remove-remote-minter-deployment
   git apply /workspace/fix-remove-remote-minter-deployment.patch
   ```

4. Or manually make the change in `apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts`:

   Change line ~127 from:
   ```typescript
   INTERCHAIN_TOKEN_FACTORY_ENCODERS.deployRemoteInterchainToken2.data({
     salt: input.salt,
     minter: input.minterAddress ?? NULL_ADDRESS,
     destinationChain,
     gasValue: input.remoteDeploymentGasFees?.gasFees?.[i].fee ?? 0n,
   })
   ```

   To:
   ```typescript
   INTERCHAIN_TOKEN_FACTORY_ENCODERS.deployRemoteInterchainToken.data({
     salt: input.salt,
     destinationChain,
     gasValue: input.remoteDeploymentGasFees?.gasFees?.[i].fee ?? 0n,
   })
   ```

5. Commit the changes:
   ```bash
   git add apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts
   git commit -m "fix: switch to new deployRemoteInterchainToken method without minter

   - Replace deprecated deployRemoteInterchainToken2 with deployRemoteInterchainToken
   - Remove minter parameter from remote deployments as per ITS v2.1.0
   - Minter is now only set on source chain, not on remote chains
   - This prevents security issues and complexity with cross-chain minter addresses"
   ```

6. Push to your fork:
   ```bash
   git push origin fix/remove-remote-minter-deployment
   ```

7. Create the PR at https://github.com/axelarnetwork/axelarjs with the following details:

## PR Title
`fix: switch to new deployRemoteInterchainToken method without minter`

## PR Description
Copy the content from `/workspace/PR_SUMMARY.md` or use:

---

### Summary
This PR updates the ITS portal to use the new `deployRemoteInterchainToken` method introduced in ITS v2.1.0 and removes the default behavior of setting a minter on remote token deployments.

### Changes Made

#### File: `apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts`
- Changed from `deployRemoteInterchainToken2` to `deployRemoteInterchainToken`
- Removed the `minter` parameter from remote deployment calls
- The minter is now only set on the source chain deployment, not on remote chains

### Background
As discussed in the Slack thread:
- The deprecated `deployRemoteInterchainToken2` method is being removed in the upcoming ITS release
- Setting a minter on remote deployments has security implications and complexity with cross-chain addresses
- The new method provides a cleaner API for the standard use case

### Impact
- **Breaking Change**: No, this maintains backward compatibility
- **Security**: Improved - removes potential security issues with cross-chain minter addresses
- **ITS Hub**: Better alignment with ITS hub accounting checks

### Testing Recommendations
1. Deploy a new interchain token through the portal
2. Verify the token is deployed correctly on the source chain with the specified minter
3. Verify remote deployments do not have a minter set
4. Test deployment to non-EVM chains (e.g., Sui) to ensure address format compatibility

### Related Links
- [ITS v2.1.0 Release](https://github.com/axelarnetwork/interchain-token-service/blob/v2.1.0/contracts/interfaces/IInterchainTokenFactory.sol#L122)
- [New deployRemoteInterchainToken method](https://github.com/axelarnetwork/interchain-token-service/blob/v2.1.0/contracts/interfaces/IInterchainTokenFactory.sol#L122)
- [Advanced method with minter support](https://github.com/axelarnetwork/interchain-token-service/blob/v2.1.0/contracts/interfaces/IInterchainTokenFactory.sol#L139)

---

## Important Notes
- This change is urgent as the deprecated method will be removed in the upcoming ITS release
- The portal will break once the deprecated method is removed if this change is not merged