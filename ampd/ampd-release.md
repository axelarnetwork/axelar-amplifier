# `ampd` Release Process (**For maintainers only**)

This document outlines the step-by-step process for releasing a new version of `ampd`. This guide is intended for team members who are responsible for managing releases.

## Prerequisites

- Access to the [axelar-amplifier](https://github.com/axelarnetwork/axelar-amplifier) repository
- Access to the private [infrastructure](https://github.com/axelarnetwork/infrastructure) repository

## Release Process

### 1. Get the release tag (Dry run)

1. Navigate to the [Update and tag release version](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/release.yaml) GitHub Action.

1. Run the workflow with the following:

    - Use workflow from: `main` branch
    - Enter `ampd` as the package input
    - **Important**: Enable "Dry run" to verify everything works correctly and make a note of the updated tag.

**Note**: To make a minor version update, at least one of your PRs should have a minor prefix in the commit message. For example, having `feat(minor-ampd)` in the commit message will bump up the minor version from 1.10.0 to 1.11.0. Similarly, for a major version update, use `feat(major-ampd)` which will bump the major version from 1.10.0 to 2.0.0.

**Important**: Major and minor releases are only allowed from the main branch.

### 2. Ensure the Changelog is updated

In general, the Changelog should be kept up-to-date in every PR that makes changes to `ampd`.

1. Create a PR to update the root-level `CHANGELOG.md` file based on the new tag from step 1 (dry-run).

1. Use this script to retrieve all changes for the release. Note that `git log ampd-v1.10.0..HEAD` should be updated accordingly:

    ```bash
    git log ampd-v1.10.0..HEAD --pretty=format:"%h %s" --name-only |
    awk '
      /^[a-f0-9]{7,}/ { hash=$1; msg=substr($0, index($0, $2)); next }
      /^ampd\// {
        if (msg ~ /\(#/ && !seen[msg]) {
          pr_num = msg
          gsub(/^.*\(#/, "", pr_num)
          gsub(/\).*/, "", pr_num)
          clean_msg = msg
          gsub(/ \(#.*\)/, "", clean_msg)
          gsub(/^[^:]+: /, "", clean_msg)  # remove type(scope):
          seen[msg] = 1
          printf "- %s [#%s](https://github.com/axelarnetwork/axelar-amplifier/pull/%s)\n", clean_msg, pr_num, pr_num
        }
      }
    '
    ```

1. Update the changelog header section with the new version information.

    Example changes:

    ```diff
    - [Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.10.0..HEAD)
    + [Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.11.0..HEAD)
    +
    + ## [v1.11.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.11.0) (2025-08-14)
    +
    + - stellar protocol v23 update [#968](https://github.com/axelarnetwork/axelar-amplifier/pull/968)
    + - use `address!` macro instead of string literal conversion [#996](https://github.com/axelarnetwork/axelar-amplifier/pull/996)
    ```

1. Merge these changes into the `main` branch.

### 3. Create a release document

1. Create and merge a PR to publish a release document on [axelar-contract-deployments](https://github.com/axelarnetwork/axelar-contract-deployments) repository. You can use the provided [template](https://github.com/axelarnetwork/axelar-contract-deployments/blob/main/releases/TEMPLATE.md). Make sure your document is added to `releases/ampd` directory of the contract deployments repository.

### 4. Update and Tag Release Version (Release)

1. Again, run the [Update and tag release version](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/release.yaml) GitHub Action with `ampd` as package and `main` as branch. For this round, disable the "Dry run" option to create the actual release tag.

1. Double-check that the tag was created successfully by visiting `https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v{VERSION}` (replace `{VERSION}` with the actual version number, e.g., `ampd-v1.11.0`).

### 5. Build the `ampd` Release

1. Navigate to the [Build and release binary and image](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/build-ampd-release.yaml) GitHub Action.

1. Run workflow using the newly created tag as input (e.g., `ampd-v1.11.0`).

1. Verify that a new release appears under the Releases section of the amplifier repository.

### 6. Deploy to Network

1. Follow this [document](https://www.notion.so/bright-ambert-2bd/How-to-deploy-ampd-release-to-live-networks-1c8c53fccb77806ba035fd2ade6b98e8?pvs=4) to update our `ampd` instance.

1. Mention the deployment in the network-specific channel regarding the rollout.

1. After deployment, verify the ampd version by running:

    ```bash
    ampd --version
    ```

    Expected output:

    ```bash
    ampd 1.11.0
    ```

1. Test the deployment with a GMP call to ensure the new version is functioning correctly.

1. Furthermore, coordinate with the DevX team to announce the release to external verifiers for testnet/mainnet.
