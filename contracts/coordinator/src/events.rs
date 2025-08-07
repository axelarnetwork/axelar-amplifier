use axelar_wasm_std::{nonempty, IntoEvent};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use router_api::ChainName;

#[derive(IntoEvent)]
pub enum Event {
    ContractsInstantiated {
        gateway: ContractInstantiation,
        voting_verifier: ContractInstantiation,
        multisig_prover: ContractInstantiation,
        chain_codec: ContractInstantiation,
        chain_name: ChainName,
        deployment_name: nonempty::String,
    },
}

#[cw_serde]
pub struct ContractInstantiation {
    pub address: Addr,
    pub code_id: u64,
}
