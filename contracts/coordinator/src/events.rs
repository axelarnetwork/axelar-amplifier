use axelar_wasm_std::IntoEvent;
use cosmwasm_std::Addr;

#[derive(IntoEvent)]
pub enum Event {
    DeployedChainContracts {
        gateway_address: Addr,
        verifier_address: Addr,
        prover_address: Addr,
    },
}
