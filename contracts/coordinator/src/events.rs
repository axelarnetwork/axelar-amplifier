use axelar_wasm_std::IntoEvent;
use cosmwasm_std::Addr;

#[derive(IntoEvent)]
pub enum ContractInstantiated {
    Gateway { address: Addr, code_id: u64 },
    VotingVerifier { address: Addr, code_id: u64 },
    MultisigProver { address: Addr, code_id: u64 },
}
