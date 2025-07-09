# ITS Portal Fix Summary

I've successfully prepared the fix for the ITS portal to use the new `deployRemoteInterchainToken` method. Since I cannot create PRs directly, I've prepared everything you need to create the PR yourself.

## Files Created

1. **`/workspace/fix-remove-remote-minter-deployment.patch`** - The git patch file with the changes
2. **`/workspace/PR_SUMMARY.md`** - Complete PR description to use when creating the PR
3. **`/workspace/create_pr_instructions.md`** - Step-by-step instructions for creating the PR
4. **`/workspace/apply_fix.sh`** - Automated script to apply the fix to your fork

## The Change

The fix updates one file:
- `apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts`

It changes:
- `deployRemoteInterchainToken2` → `deployRemoteInterchainToken`
- Removes the `minter` parameter from remote deployments

## Quick Steps to Create PR

1. **Fork** https://github.com/axelarnetwork/axelarjs
2. **Clone** your fork and run the script:
   ```bash
   git clone https://github.com/YOUR_USERNAME/axelarjs.git
   cd axelarjs
   bash /workspace/apply_fix.sh
   ```
3. **Push** the branch:
   ```bash
   git push origin fix/remove-remote-minter-deployment
   ```
4. **Create PR** at https://github.com/axelarnetwork/axelarjs
   - Title: `fix: switch to new deployRemoteInterchainToken method without minter`
   - Description: Copy from `/workspace/PR_SUMMARY.md`

## Urgency

This change is **urgent** - the ITS portal will break when the deprecated method is removed in the upcoming ITS release.