use connection_router_api::ChainName;
use cosmwasm_schema::{cw_serde, QueryResponses};
use multisig::worker_set::WorkerSet;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<(ChainName, WorkerSet)>)]
    GetChainActiveWorkerSet { chains: Vec<ChainName> },
}
