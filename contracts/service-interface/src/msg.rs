use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg<T> {
    RequestWorkerAction { message: T },
    PostWorkerReply { reply: bool, id: [u8; 32] },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(String)]
    GetServiceName {},
    #[returns(Vec<String>)]
    GetWorkerPublicKeys {},
    #[returns(Option<Addr>)]
    GetRewardsManager {},
    #[returns(Option<String>)]
    GetUnbondAllowed { worker_address: Addr },
    #[returns(WorkerState)]
    GetWorkerStatus { worker_address: Addr },
}

#[cw_serde]
pub enum WorkerState {
    Active,
    Deregistering,
    Inactive,
}
