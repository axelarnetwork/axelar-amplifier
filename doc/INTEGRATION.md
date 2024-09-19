## UNDER CONSTRUCTION

To cover:
* contract components:
    1. infra contracts
        - router, service registry, multisig, coordinator, etc
        - should not be touched unless needed
        - specific use cases where PRs to these contracts may be needed in coordination with Interop Labs team (e.g. address validation, new msg ID types, new signature schemes, etc)
    2. chain-specific contracts
        - voting verifier, gateway, multisig prover
        - mention that the ones we have in this repo are there for reference and can be used (as integrator's own peril, appreciating they're for reference only)
    3. ampd
        - for any custom chain, need to do a PR to this repo
        - suggestion that plugin is forthcoming
* step-by-step instructions:
    - we can move a lot of what is already in the public docs, here: https://docs.axelar.dev/dev/amplifier/chain-integration/introduction/#integration-process