#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response};

use connection_router_api::msg::{ExecuteMsg, QueryMsg};

use crate::events::RouterInstantiated;
use crate::msg::InstantiateMsg;
use crate::state::{Config, RouterStore, Store};

mod execute;
mod query;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;
    let nexus_gateway = deps.api.addr_validate(&msg.nexus_gateway)?;

    let config = Config {
        admin: admin.clone(),
        governance: governance.clone(),
        nexus_gateway: nexus_gateway.clone(),
    };

    RouterStore::new(deps.storage)
        .save_config(config)
        .expect("must save the config");

    Ok(Response::new().add_event(
        RouterInstantiated {
            admin,
            governance,
            nexus_gateway,
        }
        .into(),
    ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let contract = Contract::new(RouterStore::new(deps.storage));

    match msg {
        ExecuteMsg::RegisterChain {
            chain,
            gateway_address,
        } => {
            execute::require_governance(&deps, info)?;
            let gateway_address = deps.api.addr_validate(&gateway_address)?;
            execute::register_chain(deps, chain, gateway_address)
        }
        ExecuteMsg::UpgradeGateway {
            chain,
            contract_address,
        } => {
            execute::require_governance(&deps, info)?;
            let contract_address = deps.api.addr_validate(&contract_address)?;
            execute::upgrade_gateway(deps, chain, contract_address)
        }
        ExecuteMsg::FreezeChain { chain, direction } => {
            execute::require_admin(&deps, info)?;
            execute::freeze_chain(deps, chain, direction)
        }
        ExecuteMsg::UnfreezeChain { chain, direction } => {
            execute::require_admin(&deps, info)?;
            execute::unfreeze_chain(deps, chain, direction)
        }
        ExecuteMsg::RouteMessages(msgs) => Ok(contract.route_messages(info.sender, msgs)?),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

struct Contract<S>
where
    S: Store,
{
    store: S,
    #[allow(unused)]
    config: Config,
}

impl<S> Contract<S>
where
    S: Store,
{
    pub fn new(store: S) -> Self {
        let config = store.load_config().expect("config must be loaded");

        Self { store, config }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::ContractError> {
    match msg {
        QueryMsg::GetChainInfo(chain) => to_json_binary(&query::get_chain_info(deps, chain)?),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::state::CONFIG;

    use super::*;

    use connection_router_api::{error::Error, ChainName, CrossChainId, Message};
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
        Addr, CosmosMsg, Empty, OwnedDeps, WasmMsg,
    };

    const ADMIN_ADDRESS: &str = "admin";
    const GOVERNANCE_ADDRESS: &str = "governance";
    const NEXUS_GATEWAY_ADDRESS: &str = "nexus_gateway";

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();

        let config = Config {
            admin: Addr::unchecked(ADMIN_ADDRESS),
            governance: Addr::unchecked(GOVERNANCE_ADDRESS),
            nexus_gateway: Addr::unchecked(NEXUS_GATEWAY_ADDRESS),
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        deps
    }

    struct Chain {
        chain_name: ChainName,
        gateway: Addr,
    }

    fn make_chain(name: &str) -> Chain {
        Chain {
            chain_name: name.parse().unwrap(),
            gateway: Addr::unchecked(name),
        }
    }

    fn register_chain(deps: DepsMut, chain: &Chain) {
        execute(
            deps,
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterChain {
                chain: chain.chain_name.clone(),
                gateway_address: chain.gateway.to_string().try_into().unwrap(),
            },
        )
        .unwrap();
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn generate_messages(
        src_chain: &Chain,
        dest_chain: &Chain,
        nonce: &mut usize,
        count: usize,
    ) -> Vec<Message> {
        let mut msgs = vec![];
        for x in 0..count {
            *nonce += 1;
            let id = format!("tx_id:{}", nonce);
            msgs.push(Message {
                cc_id: CrossChainId {
                    id: id.parse().unwrap(),
                    chain: src_chain.chain_name.clone(),
                },
                destination_address: "idc".parse().unwrap(),
                destination_chain: dest_chain.chain_name.clone(),
                source_address: "idc".parse().unwrap(),
                payload_hash: [x as u8; 32],
            })
        }
        msgs
    }

    pub fn assert_contract_err_strings_equal(
        actual: impl Into<axelar_wasm_std::ContractError>,
        expected: impl Into<axelar_wasm_std::ContractError>,
    ) {
        assert_eq!(actual.into().to_string(), expected.into().to_string());
    }

    pub fn assert_messages_in_cosmos_msg(
        contract_addr: String,
        messages: Vec<Message>,
        cosmos_msg: CosmosMsg,
    ) {
        assert_eq!(
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr,
                msg: to_json_binary(&gateway_api::msg::ExecuteMsg::RouteMessages(messages,))
                    .unwrap(),
                funds: vec![],
            }),
            cosmos_msg
        );
    }

    #[test]
    fn successful_routing() {
        let mut deps = setup();
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let nonce: &mut usize = &mut 0;
        let messages = generate_messages(&eth, &polygon, nonce, 255);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(eth.gateway.as_str(), &[]),
            ExecuteMsg::RouteMessages(messages.clone()),
        )
        .unwrap();

        assert_eq!(res.messages.len(), 1);
        assert_messages_in_cosmos_msg(
            polygon.gateway.to_string(),
            messages.clone(),
            res.messages[0].msg.clone(),
        );

        // try to route twice
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(eth.gateway.as_str(), &[]),
            ExecuteMsg::RouteMessages(messages.clone()),
        );

        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn wrong_source_chain() {
        let mut deps = setup();
        let eth = make_chain("ethereum");
        let polygon = make_chain("polygon");

        register_chain(deps.as_mut(), &eth);
        register_chain(deps.as_mut(), &polygon);

        let messages = generate_messages(&eth, &polygon, &mut 0, 1);

        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(polygon.gateway.as_str(), &[]),
            ExecuteMsg::RouteMessages(messages),
        )
        .unwrap_err();

        assert_contract_err_strings_equal(err, Error::WrongSourceChain);
    }

    #[test]
    fn multi_chain_route() {
        let mut deps = setup();
        let chains = vec![
            make_chain("ethereum"),
            make_chain("polygon"),
            make_chain("osmosis"),
            make_chain("avalanche"),
            make_chain("moonbeam"),
        ];
        for c in &chains {
            register_chain(deps.as_mut(), c);
        }

        let nonce = &mut 0;
        let mut all_msgs_by_dest = HashMap::new();
        let mut all_msgs_by_src = HashMap::new();
        for d in &chains {
            let mut msgs = vec![];
            for s in &chains {
                let sending = generate_messages(s, d, nonce, 50);

                all_msgs_by_src
                    .entry(s.chain_name.to_string())
                    .or_insert(vec![])
                    .append(&mut sending.clone());

                msgs.append(&mut sending.clone());
            }
            all_msgs_by_dest.insert(d.chain_name.to_string(), msgs);
        }

        for s in &chains {
            let res = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(s.gateway.as_str(), &[]),
                ExecuteMsg::RouteMessages(
                    all_msgs_by_src
                        .get(&s.chain_name.to_string())
                        .unwrap()
                        .clone(),
                ),
            )
            .unwrap();

            assert_eq!(res.messages.len(), chains.len());

            for (i, d) in chains.iter().enumerate() {
                assert_messages_in_cosmos_msg(
                    d.chain_name.to_string(),
                    all_msgs_by_dest
                        .get(&d.chain_name.to_string())
                        .unwrap()
                        .clone()
                        .into_iter()
                        .filter(|m| m.cc_id.chain == s.chain_name)
                        .collect::<Vec<_>>(),
                    res.messages[i].msg.clone(),
                );
            }
        }
    }
}
