use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128,
};
use cw_multi_test::{App, ContractWrapper, Executor};

use service_registry::{
    msg::{ExecuteMsg, InstantiateMsg},
    state::{AuthorizationState, BondingState, Worker},
    ContractError,
};

pub fn mock_service_registry_execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new())
}

#[cw_serde]
pub enum MockServiceRegistryQueryMsg {
    GetActiveWorkers {
        service_name: String,
        chain_name: String,
    },
}
pub fn mock_service_registry_query(
    _deps: Deps,
    _env: Env,
    msg: MockServiceRegistryQueryMsg,
) -> StdResult<Binary> {
    match msg {
        MockServiceRegistryQueryMsg::GetActiveWorkers {
            service_name,
            chain_name: _,
        } => {
            let res = vec![
                Worker {
                    address: Addr::unchecked("addr1"),
                    bonding_state: BondingState::Bonded {
                        amount: Uint128::from(100u128),
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.clone(),
                },
                Worker {
                    address: Addr::unchecked("addr2"),
                    bonding_state: BondingState::Bonded {
                        amount: Uint128::from(100u128),
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.clone(),
                },
            ];
            Ok(to_binary(&res)?)
        }
    }
}

pub fn make_mock_service_registry(app: &mut App) -> Addr {
    let code = ContractWrapper::new(
        mock_service_registry_execute,
        |_, _, _, _: InstantiateMsg| Ok::<Response, ContractError>(Response::new()),
        mock_service_registry_query,
    );
    let code_id = app.store_code(Box::new(code));

    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("sender"),
            &InstantiateMsg {
                governance_account: Addr::unchecked("governance").into(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    contract_address
}
