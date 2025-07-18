#![cfg_attr(
    dylint_lib = "amplifier_lints",
    allow(msg_without_explicit_permissions)
)]
#![cfg_attr(dylint_lib = "amplifier_lints", allow(cosmwasm_addr_in_msg_struct))]
#![cfg_attr(dylint_lib = "amplifier_lints", allow(warn_on_unwraps))]

pub mod contract;
pub mod coordinator_contract;
pub mod gateway_contract;
pub mod multisig_contract;
pub mod multisig_prover_contract;
pub mod protocol;
pub mod rewards_contract;
pub mod router_contract;
pub mod service_registry_contract;
pub mod voting_verifier_contract;
