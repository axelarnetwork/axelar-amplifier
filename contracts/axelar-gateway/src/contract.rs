#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};

#[cfg(not(feature = "library"))]
use serde::{Deserialize, Serialize};

use crate::{
    error::GatewayError,
    msg::{ExecuteMsg, InstantiateMsg},
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, GatewayError> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, GatewayError> {
    match msg {
        ExecuteMsg::CallContract {
            contract_address,
            destination_chain,
            payload,
        } => execute::call_contract(
            deps,
            env,
            info,
            contract_address,
            destination_chain,
            payload,
        ),
    }
}

#[cfg_attr(not(feature = "library"), derive(Serialize, Deserialize))]
pub enum QueryMsg {
    Greet {},
}

#[cfg_attr(not(feature = "library"), derive(Serialize, Deserialize))]
struct QueryResp {
    message: String,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    use QueryMsg::*;

    match msg {
        Greet {} => {
            let resp = QueryResp {
                message: "Hello World".to_owned(),
            };

            to_binary(&resp)
        }
    }
}

mod execute {
    use cosmwasm_std::Event;

    use super::*;

    pub fn call_contract(
        _deps: DepsMut,
        _env: Env,
        info: MessageInfo,
        contract_address: String,
        destination_chain: String,
        payload: Binary,
    ) -> Result<Response, GatewayError> {
        if !info.funds.is_empty() {
            return Err(GatewayError::TokenReceived {});
        }

        let event = Event::new("ContractCall")
            .add_attribute("contract_address", contract_address)
            .add_attribute("destination_chain", destination_chain)
            .add_attribute("payload", payload.to_string());

        Ok(Response::new().add_event(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Event, Coin,
    };

    #[test]
    fn call_contract() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        instantiate(
            deps.as_mut(),
            env.clone(),
            mock_info("sender", &[]),
            InstantiateMsg {},
        )
        .unwrap();

        let contract_address = String::new();
        let destination_chain = String::new();
        let payload = Binary::from_base64("dead").unwrap();

        let resp = execute(
            deps.as_mut(),
            env.clone(),
            mock_info("sender", &[]),
            ExecuteMsg::CallContract {
                contract_address: contract_address.clone(),
                destination_chain: destination_chain.clone(),
                payload: payload.clone(),
            },
        )
        .unwrap();

        assert_eq!(resp.events.len(), 1);
        assert_eq!(
            resp.events[0],
            Event::new("ContractCall")
                .add_attribute("contract_address", contract_address.clone())
                .add_attribute("destination_chain", destination_chain.clone())
                .add_attribute("payload", payload.to_string())
        );

        let resp = execute(
            deps.as_mut(),
            env,
            mock_info("sender", &[Coin::new(100, "uaxl")]),
            ExecuteMsg::CallContract {
                contract_address,
                destination_chain,
                payload,
            },
        );
        assert!(resp.is_err())
    }
}
