use cosmwasm_std::Addr;
use axelar_wasm_std::IntoEvent;

#[derive(IntoEvent)]
pub enum Event {
    DeployedChainContracts {
        gateway_address: Addr,
        verifier_address: Addr,
        prover_address: Addr,
    }
}