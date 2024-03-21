use connection_router_api::ChainName;
use cosmwasm_std::Deps;
use multisig::worker_set::WorkerSet;

pub fn chains_active_worker_sets(
    _deps: Deps,
    _chains: &[ChainName],
) -> Vec<(ChainName, WorkerSet)> {
    Vec::new()
}
