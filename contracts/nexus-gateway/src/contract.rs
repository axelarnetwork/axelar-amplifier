use axelar_wasm_std::address;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, DepsMut, Empty, Env, MessageInfo, Response, Storage};
use error_stack::Report;

use crate::contract::execute::{call_contract_with_token, route_to_nexus, route_to_router};
use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::Config;
use crate::{nexus, state};

mod execute;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // any version checks should be done before here

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

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
    let axelar_gateway = address::validate_cosmwasm_address(deps.api, &msg.axelar_gateway)?;

    state::save_config(
        deps.storage,
        Config {
            nexus,
            router,
            axelar_gateway,
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
) -> Result<Response<nexus::Message>, axelar_wasm_std::error::ContractError> {
    let res = match msg.ensure_permissions(deps.storage, &info.sender, match_router, match_nexus)? {
        ExecuteMsg::CallContractWithToken {
            destination_chain,
            destination_address,
            payload,
        } => call_contract_with_token(
            deps.storage,
            deps.querier,
            info,
            destination_chain,
            destination_address,
            payload,
        )?,
        ExecuteMsg::RouteMessages(msgs) => route_to_nexus(deps.storage, msgs)?,
        ExecuteMsg::RouteMessagesFromNexus(msgs) => route_to_router(deps.storage, msgs)?,
    };

    Ok(res)
}

fn match_router(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<ContractError>> {
    Ok(state::load_config(storage)?.router)
}

fn match_nexus(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<ContractError>> {
    Ok(state::load_config(storage)?.nexus)
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::{err_contains, permission_control};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, BankMsg, Coin, CosmosMsg, QuerierResult, SubMsg, WasmMsg,
        WasmQuery,
    };
    use hex::decode;
    use router_api::CrossChainId;

    use super::*;

    const NEXUS: &str = "nexus";
    const ROUTER: &str = "router";
    const AXELAR_GATEWAY: &str = "axelar_gateway";

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, "nexus-gateway");
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    #[test]
    fn call_contract_with_token_no_token() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(NEXUS, &[]),
            ExecuteMsg::CallContractWithToken {
                destination_chain: "destinationChain".parse().unwrap(),
                destination_address: "0xD419".parse().unwrap(),
                payload: decode("bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1")
                    .unwrap()
                    .into(),
            },
        );
        assert!(res.is_err_and(|err| err_contains!(
            err.report,
            ContractError,
            ContractError::InvalidToken { .. }
        )));
    }

    #[test]
    fn call_contract_with_token() {
        let mut deps = mock_dependencies();
        deps.querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == AXELAR_GATEWAY => {
                let msg = from_json::<axelarnet_gateway::msg::QueryMsg>(msg).unwrap();

                match msg {
                    axelarnet_gateway::msg::QueryMsg::ChainName => {
                        QuerierResult::Ok(to_json_binary("axelarnet").into())
                    }
                    _ => panic!("unexpected query: {:?}", msg),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });
        instantiate_contract(deps.as_mut());

        let token = Coin {
            denom: "denom".to_string(),
            amount: 100u128.into(),
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(NEXUS, &[token.clone()]),
            ExecuteMsg::CallContractWithToken {
                destination_chain: "destinationChain".parse().unwrap(),
                destination_address: "0xD419".parse().unwrap(),
                payload: decode("bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1")
                    .unwrap()
                    .into(),
            },
        );
        assert!(res.is_ok_and(move |res| match res.messages.as_slice() {
            [SubMsg {
                msg: CosmosMsg::Bank(BankMsg::Send { to_address, amount }),
                ..
            }, SubMsg {
                msg:
                    CosmosMsg::Custom(nexus::Message {
                        token: Some(actual_token),
                        ..
                    }),
                ..
            }] => *actual_token == token && to_address == NEXUS && *amount == vec![token],
            _ => false,
        }));
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

    fn nexus_messages() -> Vec<nexus::Message> {
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
            nexus::Message {
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
            nexus::Message {
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
                axelar_gateway: AXELAR_GATEWAY.to_string(),
            },
        )
        .unwrap();
    }
}
