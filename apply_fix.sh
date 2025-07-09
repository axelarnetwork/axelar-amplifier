#!/bin/bash

# Script to apply the ITS portal fix to your fork of axelarjs

echo "This script will help you apply the ITS portal fix to your fork of axelarjs"
echo ""

# Check if we're in an axelarjs directory
if [ ! -f "package.json" ] || [ ! -d "apps/maestro" ]; then
    echo "Error: This script should be run from the root of your axelarjs fork"
    echo "Please clone your fork first:"
    echo "  git clone https://github.com/YOUR_USERNAME/axelarjs.git"
    echo "  cd axelarjs"
    exit 1
fi

# Create and checkout the branch
echo "Creating branch fix/remove-remote-minter-deployment..."
git checkout -b fix/remove-remote-minter-deployment

# Apply the fix
echo "Applying the fix..."
cat > temp_fix.patch << 'EOF'
diff --git a/apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts b/apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts
index 1234567..abcdefg 100644
--- a/apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts
+++ b/apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts
@@ -124,10 +124,9 @@ export const useDeployAndRegisterRemoteInterchainTokenMutation = () => {
     });
 
     const registerTxData = destinationChainIds.map((destinationChain, i) =>
-      INTERCHAIN_TOKEN_FACTORY_ENCODERS.deployRemoteInterchainToken2.data({
+      INTERCHAIN_TOKEN_FACTORY_ENCODERS.deployRemoteInterchainToken.data({
         salt: input.salt,
-        minter: input.minterAddress ?? NULL_ADDRESS,
         destinationChain,
         gasValue: input.remoteDeploymentGasFees?.gasFees?.[i].fee ?? 0n,
       })
     );
EOF

# Try to apply the patch
if git apply --check temp_fix.patch 2>/dev/null; then
    git apply temp_fix.patch
    rm temp_fix.patch
    echo "✓ Fix applied successfully!"
else
    # If patch fails, try direct file modification
    echo "Patch failed, attempting direct file modification..."
    FILE="apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts"
    
    # Make a backup
    cp "$FILE" "$FILE.bak"
    
    # Apply the fix using sed
    sed -i 's/deployRemoteInterchainToken2/deployRemoteInterchainToken/g' "$FILE"
    sed -i '/minter: input.minterAddress ?? NULL_ADDRESS,/d' "$FILE"
    
    echo "✓ Fix applied via direct modification!"
    rm temp_fix.patch
fi

# Stage the changes
git add apps/maestro/src/features/InterchainTokenDeployment/hooks/useDeployAndRegisterRemoteInterchainTokenMutation.ts

# Commit the changes
echo "Committing changes..."
git commit -m "fix: switch to new deployRemoteInterchainToken method without minter

- Replace deprecated deployRemoteInterchainToken2 with deployRemoteInterchainToken
- Remove minter parameter from remote deployments as per ITS v2.1.0
- Minter is now only set on source chain, not on remote chains
- This prevents security issues and complexity with cross-chain minter addresses"

echo ""
echo "✓ Changes committed successfully!"
echo ""
echo "Next steps:"
echo "1. Push to your fork: git push origin fix/remove-remote-minter-deployment"
echo "2. Go to https://github.com/axelarnetwork/axelarjs"
echo "3. Click 'New pull request'"
echo "4. Select your branch and create the PR"
echo ""
echo "PR Title: fix: switch to new deployRemoteInterchainToken method without minter"
echo ""
echo "See /workspace/PR_SUMMARY.md for the full PR description"