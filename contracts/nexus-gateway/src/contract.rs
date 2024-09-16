use axelar_core_std::nexus;
use axelar_wasm_std::address;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response, Storage};
use error_stack::Report;
use execute::route_message_with_token_to_nexus;
use migrations::v1_0_0;

use crate::contract::execute::{route_messages_to_nexus, route_messages_to_router};
use crate::error::Error;
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg};
use crate::state;
use crate::state::Config;

mod execute;
mod migrations;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    v1_0_0::migrate(deps, msg)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let nexus = address::validate_cosmwasm_address(deps.api, &msg.nexus)?;
    let router = address::validate_cosmwasm_address(deps.api, &msg.router)?;
    let axelarnet_gateway = address::validate_cosmwasm_address(deps.api, &msg.axelarnet_gateway)?;

    state::save_config(
        deps.storage,
        Config {
            nexus,
            router,
            axelarnet_gateway,
        },
    )
    .expect("config must be saved");

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<nexus::execute::Message>, axelar_wasm_std::error::ContractError> {
    let res = match msg.ensure_permissions(
        deps.storage,
        &info.sender,
        match_axelarnet_gateway,
        match_router,
        match_nexus,
    )? {
        ExecuteMsg::RouteMessageWithToken(msg) => {
            route_message_with_token_to_nexus(deps.storage, deps.querier, info, msg)?
        }
        ExecuteMsg::RouteMessages(msgs) => {
            route_messages_to_nexus(deps.storage, deps.querier, msgs)?
        }
        ExecuteMsg::RouteMessagesFromNexus(msgs) => route_messages_to_router(deps.storage, msgs)?,
    };

    Ok(res)
}

fn match_axelarnet_gateway(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<Error>> {
    Ok(state::load_config(storage)?.axelarnet_gateway)
}

fn match_router(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<Error>> {
    Ok(state::load_config(storage)?.router)
}

fn match_nexus(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<Error>> {
    Ok(state::load_config(storage)?.nexus)
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use axelar_core_std::nexus;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::{assert_err_contains, err_contains, permission_control};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_json, Coin, CosmosMsg, WasmMsg};
    use hex::decode;
    use router_api::CrossChainId;

    use super::*;

    const NEXUS: &str = "nexus";
    const ROUTER: &str = "router";
    const AXELARNET_GATEWAY: &str = "axelarnet_gateway";

    #[test]
    fn route_message_with_token_unauthorized() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("unauthorized", &[Coin::new(100, "test")]),
            ExecuteMsg::RouteMessageWithToken(router_messages()[0].clone()),
        );
        assert_err_contains!(
            res,
            permission_control::Error,
            permission_control::Error::AddressNotWhitelisted { .. }
        );
    }

    #[test]
    fn route_message_with_token_invalid_token() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(AXELARNET_GATEWAY, &[]),
            ExecuteMsg::RouteMessageWithToken(router_messages()[0].clone()),
        );
        assert_err_contains!(res, Error, Error::InvalidToken);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(
                AXELARNET_GATEWAY,
                &[Coin::new(100, "test"), Coin::new(100, "test")],
            ),
            ExecuteMsg::RouteMessageWithToken(router_messages()[0].clone()),
        );
        assert_err_contains!(res, Error, Error::InvalidToken);
    }

    #[test]
    fn route_message_with_token() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(AXELARNET_GATEWAY, &[Coin::new(100, "test")]),
            ExecuteMsg::RouteMessageWithToken(router_messages()[0].clone()),
        );
        goldie::assert_json!(assert_ok!(res));

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(AXELARNET_GATEWAY, &[Coin::new(100, "test")]),
            ExecuteMsg::RouteMessageWithToken(router_messages()[0].clone()),
        );
        assert!(assert_ok!(res).messages.is_empty());
    }

    #[test]
    fn route_to_router_unauthorized() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("unauthorized", &[]),
            ExecuteMsg::RouteMessagesFromNexus(vec![]),
        );

        assert!(res.is_err_and(|err| err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::AddressNotWhitelisted { .. }
        )));
    }

    #[test]
    fn route_to_router_with_no_msg() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(NEXUS, &[]),
            ExecuteMsg::RouteMessagesFromNexus(vec![]),
        );

        assert!(res.is_ok_and(|res| res.messages.is_empty()));
    }

    #[test]
    fn route_to_router_with_msgs() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(NEXUS, &[]),
            ExecuteMsg::RouteMessagesFromNexus(nexus_messages()),
        );

        assert!(res.is_ok_and(|res| {
            if res.messages.len() != 1 {
                return false;
            }

            match &res.messages[0].msg {
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr,
                    msg,
                    funds,
                }) => {
                    if let Ok(router_api::msg::ExecuteMsg::RouteMessages(msgs)) = from_json(msg) {
                        return *contract_addr == Addr::unchecked(ROUTER)
                            && msgs.len() == 2
                            && funds.is_empty();
                    }

                    false
                }
                _ => false,
            }
        }));
    }

    #[test]
    fn route_to_nexus_unauthorized() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("unauthorized", &[]),
            ExecuteMsg::RouteMessages(vec![]),
        );

        assert!(res.is_err_and(|err| err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::AddressNotWhitelisted { .. }
        )));
    }

    #[test]
    fn route_to_nexus_with_no_msg() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ROUTER, &[]),
            ExecuteMsg::RouteMessages(vec![]),
        );

        assert!(res.is_ok_and(|res| res.messages.is_empty()));
    }

    #[test]
    fn route_to_nexus_with_msgs_only_route_once() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let msgs = router_messages();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ROUTER, &[]),
            ExecuteMsg::RouteMessages(msgs.clone()),
        );

        assert!(res.is_ok_and(|res| res.messages.len() == 2));

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ROUTER, &[]),
            ExecuteMsg::RouteMessages(msgs.clone()),
        );

        assert!(res.is_ok_and(|res| res.messages.is_empty()));
    }

    fn nexus_messages() -> Vec<nexus::execute::Message> {
        let msg_ids = [
            HexTxHashAndEventIndex {
                tx_hash: vec![0x2f; 32].try_into().unwrap(),
                event_index: 100,
            },
            HexTxHashAndEventIndex {
                tx_hash: vec![0x23; 32].try_into().unwrap(),
                event_index: 1000,
            },
        ];
        let msgs = vec![
            nexus::execute::Message {
                source_chain: "sourceChain".parse().unwrap(),
                source_address: "0xb860".parse().unwrap(),
                destination_address: "0xD419".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                source_tx_id: msg_ids[0].tx_hash.to_vec().try_into().unwrap(),
                source_tx_index: msg_ids[0].event_index as u64,
                id: msg_ids[0].to_string(),
                token: None,
            },
            nexus::execute::Message {
                source_chain: "sourceChain".parse().unwrap(),
                source_address: "0xc860".parse().unwrap(),
                destination_address: "0xA419".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "cb9b5566c2f4876853333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                source_tx_id: msg_ids[1].tx_hash.to_vec().try_into().unwrap(),
                source_tx_index: msg_ids[1].event_index as u64,
                id: msg_ids[1].to_string(),
                token: None,
            },
        ];
        msgs
    }

    fn router_messages() -> Vec<router_api::Message> {
        let msgs = vec![
            router_api::Message {
                cc_id: CrossChainId {
                    source_chain: "sourceChain".parse().unwrap(),
                    message_id: "0x2fe4:0".parse().unwrap(),
                },
                source_address: "0xb860".parse().unwrap(),
                destination_address: "0xD419".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            },
            router_api::Message {
                cc_id: CrossChainId {
                    source_chain: "sourceChain".parse().unwrap(),
                    message_id: "0x6b33:10".parse().unwrap(),
                },
                source_address: "0x70725".parse().unwrap(),
                destination_address: "0x7FAD".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            },
        ];
        msgs
    }

    fn instantiate_contract(deps: DepsMut) {
        instantiate(
            deps,
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                nexus: NEXUS.to_string(),
                router: ROUTER.to_string(),
                axelarnet_gateway: AXELARNET_GATEWAY.to_string(),
            },
        )
        .unwrap();
    }
}
