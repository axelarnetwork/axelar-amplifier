use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg<T, S> {
    RequestWorkerAction { message: T },
    PostWorkerReply { reply: S },
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
