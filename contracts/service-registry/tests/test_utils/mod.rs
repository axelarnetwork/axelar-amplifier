use connection_router::state::ChainName;
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};
use service_registry::{
    contract::{execute, instantiate, query},
    msg::{InstantiateMsg, QueryMsg},
    state::Worker,
};

pub fn instantiate_contract(app: &mut App) -> (Addr, Addr) {
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();

    (contract_addr, governance)
}

pub fn get_active_workers(
    app: &mut App,
    contract_addr: Addr,
    service_name: &str,
    chain_name: ChainName,
) -> Vec<Worker> {
    app.wrap()
        .query_wasm_smart(
            contract_addr,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap()
}
