use axelar_wasm_std::IntoEvent;
use cosmwasm_std::Addr;
use router_api::ChainName;

#[derive(IntoEvent)]
pub enum Event {
    ChainsSupportRegistered {
        verifier: Addr,
        service_name: String,
        chains: Vec<ChainName>,
    },
    ChainsSupportDeregistered {
        verifier: Addr,
        service_name: String,
        chains: Vec<ChainName>,
    },
}
