# `ampd` Release Process

**For maintainers only**

This document outlines the step-by-step process for releasing a new version of `ampd`. This guide is intended for team members who are responsible for managing releases.

## Prerequisites

- Access to the [axelar-amplifier](https://github.com/axelarnetwork/axelar-amplifier) repository
- Access to the private [infrastructure](https://github.com/axelarnetwork/infrastructure) repository

## Release Process

### 1. Get the release tag (Dry run)

1. Navigate to the [Update and tag release version](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/release.yaml) GitHub Action.
2. Run the workflow with the following:
   - Use workflow from: `main` branch
   - Enter `ampd` as the package input
   - **IMPORTANT**: Enable "Dry run" to verify everything works correctly and make a note of the updated tag.


### 2. Ensure the Changelog is updated

In general, Changelog should be kept up-to-date in every PR that makes changes to `ampd`.
1. Create a PR to update the root level `CHANGELOG.md` file based on the new tag from step 1 (dry-run).
2. Update the changelog header section with the new version information.

Example changes:

```diff
- [Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.5.0..HEAD)
+ [Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.5.1..HEAD)
+ 
+ ## [v1.5.1](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.5.1) (2025-03-26)
+ 
+ [Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.5.0..ampd-v1.5.1)
+ 
+ - Fix arithmetic operations with XRPLTokenAmount [#780](https://github.com/axelarnetwork/axelar-amplifier/pull/780)
```

3. Merge these changes into the `main` branch.


### 3. Create a release document 

1. Create and merge a PR to publish a release document on [axelar-contract-deployments](https://github.com/axelarnetwork/axelar-contract-deployments) repository. You can use the provided [template](https://github.com/axelarnetwork/axelar-contract-deployments/blob/main/releases/TEMPLATE.md). Make sure your document is added to `releases/ampd` directory of the contract deployments repository.


### 4. Update and Tag Release Version (Dry run)

1. Again, run the [Update and tag release version](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/release.yaml) GitHub Action with `ampd` as package and `main` as branch. For this round, disable the "Dry run" option to create the actual release tag.


### 5. Build the `ampd` Release

1. Navigate to the [Build and release binary and image](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/build-ampd-release.yaml) GitHub Action.
2. Run workflow using the newly created tag as input.
3. Verify that a new release appears under the Releases section of the amplifier repository.


### 6. Deploy to Network

Follow this [document](https://www.notion.so/bright-ambert-2bd/How-to-deploy-ampd-release-to-live-networks-1c8c53fccb77806ba035fd2ade6b98e8?pvs=4) to update our `ampd` instance.

Furthermore, coordinate with the DevX team to announce the release to external verifiers for testnet/mainnet.
