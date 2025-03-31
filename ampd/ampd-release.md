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


### 2. Update the Changelog

1. Create a PR to update the root level `CHANGELOG.md` file based on the new tag from step 1.
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

3. Create a PR with these changes and merge it to the `main` branch.



### 3. Update and Tag Release Version (Dry run)

1. Again, run the [Update and tag release version](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/release.yaml) GitHub Action with `ampd` as package and `main` as branch. For this round, disable the "Dry run" option to create the actual release tag.



### 4. Build the `ampd` Release

1. Navigate to the [Build and release binary and image](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/build-ampd-release.yaml) GitHub Action.
2. Run workflow using the newly created tag as input.
3. Verify that a new release appears under the Releases section of the amplifier repository.

### 5. Deploy to Network

#### 5.1 Update Infrastructure Configuration

1. Create a PR in the private [infrastructure](https://github.com/axelarnetwork/infrastructure) repository to update the `ampd` tag in the Helm charts for your target network (devnet, testnet, or stagenet).

   Example PR for reference: [link](https://github.com/axelarnetwork/infrastructure/commit/e7dc80160404b75ac8e3b850d834a53e76680eab)

#### 5.2 Merge Infrastructure PR

1. Get the necessary reviews and merge your infrastructure PR.

#### 5.3 Run Deployment Action

1. Navigate to the [infrastructure actions page](https://github.com/axelarnetwork/infrastructure/actions).
2. Select the corresponding action for your target network (e.g., "Run testnet") and run the workflow.
3. **IMPORTANT**: Select `true` for the "Terragrunt apply" option to actually apply the changes.
