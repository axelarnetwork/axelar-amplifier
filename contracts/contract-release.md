# Contract Release Process (**For maintainers only**)

This document outlines the step-by-step process for releasing a new version of a contract. This guide is intended for team members who are responsible for managing releases.

## Prerequisites

- Access to the [axelar-amplifier](https://github.com/axelarnetwork/axelar-amplifier) repository
- Access to the private [infrastructure](https://github.com/axelarnetwork/infrastructure) repository

## Release Process

### 1. Get the release tag (Dry run)

1. Navigate to the [Update and tag release version](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/release.yaml) GitHub Action.

1. Run the workflow with the following:

    - Use workflow from: `main` branch
    - Enter the contract name as the package input, e.g. `voting-verifier` (referred to as `{CONTRACT_NAME}` below)
    - **Important**: Enable "Dry run" to verify everything works correctly and make a note of the updated tag.

**Note**: To make a minor version update, at least one of your PRs should have a minor prefix in the commit message. For example, having `feat(minor-{CONTRACT_NAME})` in the commit message will bump up the minor version from 1.10.0 to 1.11.0. Similarly, for a major version update, use `feat(major-{CONTRACT_NAME})` which will bump the major version from 1.10.0 to 2.0.0.

**Important**: Major and minor releases are only allowed from the main branch.

### 2. Ensure the Changelog is updated

In general, the Changelog should be kept up-to-date in every PR that makes changes to the contract.

1. Create a PR to update the contract's root-level `CHANGELOG.md` file based on the new tag from step 1 (dry-run), i.e. contracts/{CONTRACT_NAME}/CHANGELOG.md

1. Use this script to retrieve all changes for the release. Replace `{CONTRACT_NAME}` with the actual contract name and `{VERSION}` with the actual version number, e.g., `voting-verifier-v1.2.0`:

    ```bash
    git log {CONTRACT_NAME}-{VERSION}..HEAD --pretty=format:"%h %s" --name-only |
    awk '
      /^[a-f0-9]{7,}/ { hash=$1; msg=substr($0, index($0, $2)); next }
      /^{CONTRACT_NAME}\// {
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
    - [Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/voting-verifier-v1.10.0..HEAD)
    + [Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/voting-verifier-v1.11.0..HEAD)
    +
    + ## [v1.11.0](https://github.com/axelarnetwork/axelar-amplifier/tree/voting-verifier-v1.11.0) (2025-08-14)
    +
    + - stellar protocol v23 update [#968](https://github.com/axelarnetwork/axelar-amplifier/pull/968)
    + - use `address!` macro instead of string literal conversion [#996](https://github.com/axelarnetwork/axelar-amplifier/pull/996)
    ```

1. Merge these changes into the `main` branch.

### 3. Create a release document

1. If necessary, create and merge a PR to publish a release document on [axelar-contract-deployments](https://github.com/axelarnetwork/axelar-contract-deployments) repository. You can use the provided [template](https://github.com/axelarnetwork/axelar-contract-deployments/blob/main/releases/TEMPLATE.md). Make sure your document is added to `releases/cosmwasm` directory of the contract deployments repository.

### 4. Update and Tag Release Version (Release)

1. Again, run the [Update and tag release version](https://github.com/axelarnetwork/axelar-amplifier/actions/workflows/release.yaml) GitHub Action with the contract name as package and `main` as branch. For this round, disable the "Dry run" option to create the actual release tag.

1. Double-check that the tag was created successfully by visiting `https://github.com/axelarnetwork/axelar-amplifier/tree/{CONTRACT_NAME}-v{VERSION}` (replace `{CONTRACT_NAME}` with the actual contract name and `{VERSION}` with the actual version number, e.g., `voting-verifier-v1.2.0`).
