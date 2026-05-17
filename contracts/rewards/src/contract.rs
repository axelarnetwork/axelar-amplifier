use axelar_wasm_std::{address, nonempty, permission_control};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_json, to_json_binary, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Reply,
    Response, SubMsg,
};
use error_stack::ResultExt;
use itertools::Itertools;

use crate::error::ContractError;
use crate::events;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{self, Config, DistributionPayload, PoolId, SendDestination, CONFIG};

mod execute;
mod migrations;
mod query;

pub use migrations::{migrate, MigrateMsg};

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const REWARDS_DISTRIBUTION_REPLY_ID: u64 = 1;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
    permission_control::set_governance(deps.storage, &governance)?;

    CONFIG.save(
        deps.storage,
        &Config {
            rewards_denom: msg.rewards_denom,
        },
    )?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::RecordParticipation {
            chain_name,
            event_id,
            verifier_address,
        } => {
            let verifier_address = address::validate_cosmwasm_address(deps.api, &verifier_address)?;
            let pool_id = PoolId {
                chain_name,
                contract: info.sender,
            };
            execute::record_participation(
                deps.storage,
                event_id,
                verifier_address,
                pool_id,
                env.block.height,
            )?;

            Ok(Response::new())
        }
        ExecuteMsg::AddRewards { pool_id } => {
            let amount = info
                .funds
                .iter()
                .find(|coin| coin.denom == state::load_config(deps.storage).rewards_denom)
                .filter(|_| info.funds.len() == 1) // filter here to make sure expected denom is the only one attached to this message, and other funds aren't silently swallowed
                .ok_or(ContractError::WrongDenom)?
                .amount;

            execute::add_rewards(
                deps.storage,
                PoolId::try_from_msg_pool_id(deps.api, pool_id)?,
                nonempty::Uint128::try_from(amount).change_context(ContractError::ZeroRewards)?,
            )?;

            Ok(Response::new())
        }
        ExecuteMsg::DistributeRewards {
            pool_id,
            epoch_count,
        } => {
            let pool_id = PoolId::try_from_msg_pool_id(deps.api, pool_id)?;
            let rewards_distribution = execute::distribute_rewards(
                deps.storage,
                pool_id.clone(),
                env.block.height,
                epoch_count,
            )?;

            let denom = state::load_config(deps.storage).rewards_denom;
            let submsgs = rewards_distribution
                .rewards
                .clone()
                .into_iter()
                .sorted()
                .map(|(verifier, amount)| {
                    let (to_address, destination) = match &verifier.proxy_address {
                        Some(proxy) => (proxy.clone(), SendDestination::Proxy),
                        None => (verifier.verifier_address.clone(), SendDestination::Verifier),
                    };
                    let payload = DistributionPayload {
                        pool_id: pool_id.clone(),
                        verifier_address: verifier.verifier_address.clone(),
                        proxy_address: verifier.proxy_address.clone(),
                        amount,
                        destination,
                    };
                    let bank_msg = BankMsg::Send {
                        to_address: to_address.into(),
                        amount: vec![Coin {
                            denom: denom.clone(),
                            amount,
                        }],
                    };
                    let encoded = to_json_binary(&payload)
                        .change_context(ContractError::SerializeReplyPayload)?;
                    Ok::<_, error_stack::Report<ContractError>>(
                        SubMsg::reply_on_error(bank_msg, REWARDS_DISTRIBUTION_REPLY_ID)
                            .with_payload(encoded),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Response::new()
                .add_submessages(submsgs)
                .add_event(events::Event::from(rewards_distribution)))
        }
        ExecuteMsg::UpdatePoolParams { params, pool_id } => {
            execute::update_pool_params(
                deps.storage,
                &PoolId::try_from_msg_pool_id(deps.api, pool_id)?,
                params,
                env.block.height,
            )?;

            Ok(Response::new())
        }
        ExecuteMsg::CreatePool { params, pool_id } => {
            execute::create_pool(
                deps.storage,
                params,
                env.block.height,
                PoolId::try_from_msg_pool_id(deps.api, pool_id)?,
            )?;

            Ok(Response::new())
        }
        ExecuteMsg::SetVerifierProxy { proxy_address } => {
            execute::set_verifier_proxy(
                deps.storage,
                &deps.api.addr_validate(&proxy_address)?,
                &info.sender,
            )?;

            Ok(Response::new())
        }
        ExecuteMsg::RemoveVerifierProxy {} => {
            execute::remove_verifier_proxy(deps.storage, &info.sender);

            Ok(Response::new())
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match reply.id {
        REWARDS_DISTRIBUTION_REPLY_ID => handle_distribution_failure(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
    .map_err(axelar_wasm_std::error::ContractError::from)
}

fn handle_distribution_failure(
    deps: DepsMut,
    reply: Reply,
) -> Result<Response, error_stack::Report<ContractError>> {
    let payload: DistributionPayload = from_json(&reply.payload)
        .change_context(ContractError::DeserializeReplyPayload)?;

    match payload.destination {
        SendDestination::Proxy => {
            let proxy_address = payload
                .proxy_address
                .clone()
                .expect("proxy destination requires a proxy address");
            let denom = state::load_config(deps.storage).rewards_denom;
            let fallback_payload = DistributionPayload {
                destination: SendDestination::Verifier,
                ..payload.clone()
            };
            let bank_msg = BankMsg::Send {
                to_address: payload.verifier_address.to_string(),
                amount: vec![Coin {
                    denom,
                    amount: payload.amount,
                }],
            };
            let encoded = to_json_binary(&fallback_payload)
                .change_context(ContractError::SerializeReplyPayload)?;
            Ok(Response::new()
                .add_submessage(
                    SubMsg::reply_on_error(bank_msg, REWARDS_DISTRIBUTION_REPLY_ID)
                        .with_payload(encoded),
                )
                .add_event(events::Event::ProxySendFailed {
                    pool_id: payload.pool_id,
                    verifier_address: payload.verifier_address,
                    proxy_address,
                    amount: payload.amount,
                }))
        }
        SendDestination::Verifier => {
            let mut pool = state::load_rewards_pool(deps.storage, payload.pool_id.clone())?;
            pool.balance = pool
                .balance
                .checked_add(payload.amount)
                .map_err(Into::<ContractError>::into)
                .map_err(error_stack::Report::from)?;
            state::save_rewards_pool(deps.storage, &pool)?;
            Ok(Response::new().add_event(events::Event::VerifierSendFailed {
                pool_id: payload.pool_id,
                verifier_address: payload.verifier_address,
                proxy_address: payload.proxy_address,
                amount: payload.amount,
            }))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::RewardsPool { pool_id } => {
            let pool = query::rewards_pool(
                deps.storage,
                PoolId::try_from_msg_pool_id(deps.api, pool_id)?,
                env.block.height,
            )?;
            to_json_binary(&pool)
                .change_context(ContractError::SerializeResponse)
                .map_err(axelar_wasm_std::error::ContractError::from)
        }
        QueryMsg::VerifierParticipation { pool_id, epoch_num } => {
            let tally = query::participation(
                deps.storage,
                PoolId::try_from_msg_pool_id(deps.api, pool_id)?,
                epoch_num,
                env.block.height,
            )?;
            to_json_binary(&tally)
                .change_context(ContractError::SerializeResponse)
                .map_err(axelar_wasm_std::error::ContractError::from)
        }
        QueryMsg::VerifierProxy { verifier } => {
            let proxy =
                state::may_load_verifier_proxy(deps.storage, &deps.api.addr_validate(&verifier)?)?;
            to_json_binary(&proxy)
                .change_context(ContractError::SerializeResponse)
                .map_err(axelar_wasm_std::error::ContractError::from)
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{coins, Addr, BlockInfo, Uint128};
    use cw_multi_test::{App, ContractWrapper, Executor};
    use router_api::{chain_name, cosmos_addr, cosmos_address};

    use super::*;
    use crate::msg::{ExecuteMsg, InstantiateMsg, Params, PoolId, QueryMsg, RewardsPool};

    const USER: &str = "user";
    const VERIFIER: &str = "verifier";
    const POOL_CONTRACT: &str = "pool_contract";
    const GOVERNANCE: &str = "governance";
    const ROUTER: &str = "router";
    const MOCK_CHAIN: &str = "mock-chain";

    /// Tests that the contract entry points (instantiate, query and execute) work as expected.
    /// Instantiates the contract and calls each of the 4 ExecuteMsg variants.
    /// Adds rewards to the pool, updates the rewards params, records some participation
    /// events and then distributes the rewards.
    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_rewards_flow() {
        let chain_name = chain_name!(MOCK_CHAIN);
        let user = cosmos_addr!(USER);
        let verifier = cosmos_addr!(VERIFIER);
        let pool_contract = cosmos_addr!(POOL_CONTRACT);

        const AXL_DENOMINATION: &str = "uaxl";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(storage, &user, coins(100000, AXL_DENOMINATION))
                .unwrap()
        });
        let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
        let code_id = app.store_code(Box::new(code));

        let governance_address = cosmos_addr!(GOVERNANCE);
        let initial_params = Params {
            epoch_duration: 10u64.try_into().unwrap(),
            rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
            participation_threshold: (1, 2).try_into().unwrap(),
        };
        let contract_address = app
            .instantiate_contract(
                code_id,
                cosmos_addr!(ROUTER),
                &InstantiateMsg {
                    governance_address: governance_address.to_string(),
                    rewards_denom: AXL_DENOMINATION.to_string(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let pool_id = PoolId {
            chain_name: chain_name.clone(),
            contract: pool_contract.to_string(),
        };

        let res = app.execute_contract(
            governance_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::CreatePool {
                params: initial_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        let rewards = 200;
        let res = app.execute_contract(
            user.clone(),
            contract_address.clone(),
            &ExecuteMsg::AddRewards {
                pool_id: pool_id.clone(),
            },
            &coins(rewards, AXL_DENOMINATION),
        );
        assert!(res.is_ok());

        let updated_params = Params {
            rewards_per_epoch: Uint128::from(150u128).try_into().unwrap(),
            ..initial_params
        };
        let res = app.execute_contract(
            governance_address,
            contract_address.clone(),
            &ExecuteMsg::UpdatePoolParams {
                params: updated_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        let res = app.execute_contract(
            pool_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some event".try_into().unwrap(),
                verifier_address: verifier.to_string(),
            },
            &[],
        );
        assert!(res.is_ok());

        let res = app.execute_contract(
            pool_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some other event".try_into().unwrap(),
                verifier_address: verifier.to_string(),
            },
            &[],
        );
        assert!(res.is_ok());

        // check the rewards pool
        let res: RewardsPool = app
            .wrap()
            .query_wasm_smart(contract_address.clone(), &QueryMsg::RewardsPool { pool_id })
            .unwrap();
        assert_eq!(
            res,
            RewardsPool {
                balance: rewards.into(),
                epoch_duration: updated_params.epoch_duration.into(),
                rewards_per_epoch: updated_params.rewards_per_epoch.into(),
                participation_threshold: updated_params.participation_threshold,
                current_epoch_num: 0u64.into(),
                last_distribution_epoch: None
            }
        );

        // need to change the block height, so we can claim rewards
        let old_height = app.block_info().height;
        app.set_block(BlockInfo {
            height: old_height + u64::from(initial_params.epoch_duration) * 2,
            ..app.block_info()
        });

        let res = app.execute_contract(
            user,
            contract_address.clone(),
            &ExecuteMsg::DistributeRewards {
                pool_id: PoolId {
                    chain_name: chain_name.clone(),
                    contract: pool_contract.to_string(),
                },
                epoch_count: None,
            },
            &[],
        );
        assert!(res.is_ok());

        // verifier should have been sent the appropriate rewards
        let balance = app
            .wrap()
            .query_balance(verifier, AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, Uint128::from(150u128));
    }

    /// Tests that rewards are properly distributed with respect to the verifier proxy address,
    /// and that the proxy address can be correctly queried
    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_rewards_with_proxy() {
        let chain_name = chain_name!(MOCK_CHAIN);
        let user = cosmos_addr!(USER);
        let verifier = cosmos_addr!(VERIFIER);
        let pool_contract = cosmos_addr!(POOL_CONTRACT);

        const AXL_DENOMINATION: &str = "uaxl";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(storage, &user, coins(100000, AXL_DENOMINATION))
                .unwrap()
        });
        let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
        let code_id = app.store_code(Box::new(code));

        let governance_address = cosmos_addr!(GOVERNANCE);
        let params = Params {
            epoch_duration: 10u64.try_into().unwrap(),
            rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
            participation_threshold: (1, 2).try_into().unwrap(),
        };
        let contract_address = app
            .instantiate_contract(
                code_id,
                cosmos_addr!(ROUTER),
                &InstantiateMsg {
                    governance_address: governance_address.to_string(),
                    rewards_denom: AXL_DENOMINATION.to_string(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let pool_id = PoolId {
            chain_name: chain_name.clone(),
            contract: pool_contract.to_string(),
        };

        app.execute_contract(
            governance_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::CreatePool {
                params: params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        )
        .unwrap();

        let proxy = cosmos_addr!("proxy");

        app.execute_contract(
            verifier.clone(),
            contract_address.clone(),
            &ExecuteMsg::SetVerifierProxy {
                proxy_address: cosmos_address!("proxy"),
            },
            &[],
        )
        .unwrap();

        // query the proxy
        let res: Option<Addr> = app
            .wrap()
            .query_wasm_smart(
                contract_address.clone(),
                &QueryMsg::VerifierProxy {
                    verifier: cosmos_address!(VERIFIER),
                },
            )
            .unwrap();
        assert_eq!(res, Some(proxy.clone()));

        let rewards = 200;
        app.execute_contract(
            user.clone(),
            contract_address.clone(),
            &ExecuteMsg::AddRewards {
                pool_id: pool_id.clone(),
            },
            &coins(rewards, AXL_DENOMINATION),
        )
        .unwrap();

        app.execute_contract(
            pool_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some event".try_into().unwrap(),
                verifier_address: verifier.to_string(),
            },
            &[],
        )
        .unwrap();

        // need to change the block height, so we can claim rewards
        let old_height = app.block_info().height;
        app.set_block(BlockInfo {
            height: old_height + u64::from(params.epoch_duration) * 2,
            ..app.block_info()
        });

        app.execute_contract(
            user.clone(),
            contract_address.clone(),
            &ExecuteMsg::DistributeRewards {
                pool_id: PoolId {
                    chain_name: chain_name.clone(),
                    contract: pool_contract.to_string(),
                },
                epoch_count: None,
            },
            &[],
        )
        .unwrap();

        // verifier should have been sent the appropriate rewards
        let balance = app.wrap().query_balance(proxy, AXL_DENOMINATION).unwrap();
        assert_eq!(balance.amount, Uint128::from(params.rewards_per_epoch));

        // remove the proxy address
        app.execute_contract(
            verifier.clone(),
            contract_address.clone(),
            &ExecuteMsg::RemoveVerifierProxy {},
            &[],
        )
        .unwrap();

        // query the proxy
        let res: Option<Addr> = app
            .wrap()
            .query_wasm_smart(
                contract_address.clone(),
                &QueryMsg::VerifierProxy {
                    verifier: cosmos_address!(VERIFIER),
                },
            )
            .unwrap();
        assert_eq!(res, None);

        app.execute_contract(
            pool_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some other event".try_into().unwrap(),
                verifier_address: verifier.to_string(),
            },
            &[],
        )
        .unwrap();

        // need to change the block height, so we can claim rewards
        let old_height = app.block_info().height;
        app.set_block(BlockInfo {
            height: old_height + u64::from(params.epoch_duration) * 2,
            ..app.block_info()
        });

        app.execute_contract(
            user,
            contract_address.clone(),
            &ExecuteMsg::DistributeRewards {
                pool_id: PoolId {
                    chain_name: chain_name.clone(),
                    contract: pool_contract.to_string(),
                },
                epoch_count: None,
            },
            &[],
        )
        .unwrap();

        // verifier should have been sent the appropriate rewards
        let balance = app
            .wrap()
            .query_balance(verifier, AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, Uint128::from(params.rewards_per_epoch));
    }

    // test that pool parameter updates take effect in the current epoch, even when there is
    // an existing tally
    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn params_updated_in_current_epoch_when_existing_tallies() {
        let chain_name = chain_name!(MOCK_CHAIN);
        let user = cosmos_addr!(USER);
        let verifier = cosmos_addr!(VERIFIER);
        let pool_contract = cosmos_addr!(POOL_CONTRACT);

        const AXL_DENOMINATION: &str = "uaxl";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(storage, &user, coins(100000, AXL_DENOMINATION))
                .unwrap()
        });
        let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
        let code_id = app.store_code(Box::new(code));

        let governance_address = cosmos_addr!(GOVERNANCE);
        let initial_params = Params {
            epoch_duration: 10u64.try_into().unwrap(),
            rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
            participation_threshold: (1, 2).try_into().unwrap(),
        };
        let contract_address = app
            .instantiate_contract(
                code_id,
                cosmos_addr!(ROUTER),
                &InstantiateMsg {
                    governance_address: governance_address.to_string(),
                    rewards_denom: AXL_DENOMINATION.to_string(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let pool_id = PoolId {
            chain_name: chain_name.clone(),
            contract: pool_contract.to_string(),
        };

        let res = app.execute_contract(
            governance_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::CreatePool {
                params: initial_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        app.execute_contract(
            pool_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some event".try_into().unwrap(),
                verifier_address: verifier.to_string(),
            },
            &[],
        )
        .unwrap();

        let updated_params = Params {
            rewards_per_epoch: initial_params
                .rewards_per_epoch
                .into_inner()
                .checked_add(Uint128::from(1000u128))
                .unwrap()
                .try_into()
                .unwrap(),
            ..initial_params
        };
        let res = app.execute_contract(
            governance_address,
            contract_address.clone(),
            &ExecuteMsg::UpdatePoolParams {
                params: updated_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        // check the rewards pool
        let res: RewardsPool = app
            .wrap()
            .query_wasm_smart(
                contract_address.clone(),
                &QueryMsg::RewardsPool {
                    pool_id: pool_id.clone(),
                },
            )
            .unwrap();
        assert_eq!(
            res,
            RewardsPool {
                balance: Uint128::zero(),
                epoch_duration: updated_params.epoch_duration.into(),
                rewards_per_epoch: updated_params.rewards_per_epoch.into(),
                participation_threshold: updated_params.participation_threshold,
                current_epoch_num: 0u64.into(),
                last_distribution_epoch: None
            }
        );

        // need to change the block height, so we can claim rewards
        let old_height = app.block_info().height;
        app.set_block(BlockInfo {
            height: old_height + u64::from(updated_params.epoch_duration) * 2,
            ..app.block_info()
        });

        app.execute_contract(
            user.clone(),
            contract_address.clone(),
            &ExecuteMsg::AddRewards {
                pool_id: pool_id.clone(),
            },
            &coins(
                updated_params.rewards_per_epoch.into_inner().u128(),
                AXL_DENOMINATION,
            ),
        )
        .unwrap();

        app.execute_contract(
            user,
            contract_address.clone(),
            &ExecuteMsg::DistributeRewards {
                pool_id: PoolId {
                    chain_name: chain_name.clone(),
                    contract: pool_contract.to_string(),
                },
                epoch_count: None,
            },
            &[],
        )
        .unwrap();

        // verifier should have been sent the appropriate rewards
        let balance = app
            .wrap()
            .query_balance(verifier, AXL_DENOMINATION)
            .unwrap();
        assert_eq!(
            balance.amount,
            Uint128::from(updated_params.rewards_per_epoch)
        );
    }

    // test that pool parameter updates take effect in the current epoch when there are no tallies
    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn params_updated_in_current_epoch_with_no_existing_tallies() {
        let chain_name = chain_name!(MOCK_CHAIN);
        let user = cosmos_addr!(USER);
        let verifier = cosmos_addr!(VERIFIER);
        let pool_contract = cosmos_addr!(POOL_CONTRACT);

        const AXL_DENOMINATION: &str = "uaxl";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(storage, &user, coins(100000, AXL_DENOMINATION))
                .unwrap()
        });
        let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
        let code_id = app.store_code(Box::new(code));

        let governance_address = cosmos_addr!(GOVERNANCE);
        let initial_params = Params {
            epoch_duration: 10u64.try_into().unwrap(),
            rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
            participation_threshold: (1, 2).try_into().unwrap(),
        };
        let contract_address = app
            .instantiate_contract(
                code_id,
                cosmos_addr!(ROUTER),
                &InstantiateMsg {
                    governance_address: governance_address.to_string(),
                    rewards_denom: AXL_DENOMINATION.to_string(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let pool_id = PoolId {
            chain_name: chain_name.clone(),
            contract: pool_contract.to_string(),
        };

        let res = app.execute_contract(
            governance_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::CreatePool {
                params: initial_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        let updated_params = Params {
            rewards_per_epoch: initial_params
                .rewards_per_epoch
                .into_inner()
                .checked_add(Uint128::from(1000u128))
                .unwrap()
                .try_into()
                .unwrap(),
            ..initial_params
        };

        let res = app.execute_contract(
            governance_address,
            contract_address.clone(),
            &ExecuteMsg::UpdatePoolParams {
                params: updated_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        // check the rewards pool
        let res: RewardsPool = app
            .wrap()
            .query_wasm_smart(
                contract_address.clone(),
                &QueryMsg::RewardsPool {
                    pool_id: pool_id.clone(),
                },
            )
            .unwrap();
        assert_eq!(
            res,
            RewardsPool {
                balance: Uint128::zero(),
                epoch_duration: updated_params.epoch_duration.into(),
                rewards_per_epoch: updated_params.rewards_per_epoch.into(),
                participation_threshold: updated_params.participation_threshold,
                current_epoch_num: 0u64.into(),
                last_distribution_epoch: None
            }
        );

        // test distributing the rewards now

        // add some participation now, so we can distribute rewards
        app.execute_contract(
            pool_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some event".try_into().unwrap(),
                verifier_address: verifier.to_string(),
            },
            &[],
        )
        .unwrap();

        // need to change the block height, so we can claim rewards
        let old_height = app.block_info().height;
        app.set_block(BlockInfo {
            height: old_height + u64::from(updated_params.epoch_duration) * 2,
            ..app.block_info()
        });

        app.execute_contract(
            user.clone(),
            contract_address.clone(),
            &ExecuteMsg::AddRewards {
                pool_id: pool_id.clone(),
            },
            &coins(
                updated_params.rewards_per_epoch.into_inner().u128(),
                AXL_DENOMINATION,
            ),
        )
        .unwrap();

        app.execute_contract(
            user,
            contract_address.clone(),
            &ExecuteMsg::DistributeRewards {
                pool_id: PoolId {
                    chain_name: chain_name.clone(),
                    contract: pool_contract.to_string(),
                },
                epoch_count: None,
            },
            &[],
        )
        .unwrap();

        // verifier should have been sent the appropriate rewards
        let balance = app
            .wrap()
            .query_balance(verifier, AXL_DENOMINATION)
            .unwrap();
        assert_eq!(
            balance.amount,
            Uint128::from(updated_params.rewards_per_epoch)
        );
    }

    // test that pool parameter updates take effect in the current epoch when shortening the epoch such that a new epoch
    // is immediately created. If the params shorten the epoch duration such that the current epoch should end, the contract
    // immediately ends the current epoch and starts a new one. This tests that things like rewards_per_epoch are updated correctly
    // for the epoch that was ended
    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn params_updated_in_current_epoch_when_shortening_epoch() {
        let chain_name = chain_name!(MOCK_CHAIN);
        let user = cosmos_addr!(USER);
        let verifier = cosmos_addr!(VERIFIER);
        let pool_contract = cosmos_addr!(POOL_CONTRACT);

        const AXL_DENOMINATION: &str = "uaxl";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(storage, &user, coins(100000, AXL_DENOMINATION))
                .unwrap()
        });
        let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
        let code_id = app.store_code(Box::new(code));

        let governance_address = cosmos_addr!(GOVERNANCE);
        let initial_params = Params {
            epoch_duration: 10u64.try_into().unwrap(),
            rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
            participation_threshold: (1, 2).try_into().unwrap(),
        };
        let contract_address = app
            .instantiate_contract(
                code_id,
                cosmos_addr!(ROUTER),
                &InstantiateMsg {
                    governance_address: governance_address.to_string(),
                    rewards_denom: AXL_DENOMINATION.to_string(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let pool_id = PoolId {
            chain_name: chain_name.clone(),
            contract: pool_contract.to_string(),
        };

        let res = app.execute_contract(
            governance_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::CreatePool {
                params: initial_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        app.execute_contract(
            pool_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some event".try_into().unwrap(),
                verifier_address: verifier.to_string(),
            },
            &[],
        )
        .unwrap();

        // advance the height two blocks
        let old_height = app.block_info().height;
        app.set_block(BlockInfo {
            height: old_height + 2,
            ..app.block_info()
        });

        // shorten the epoch duration to 1 block. We are already two blocks in, so this will end the epoch
        // also, increase the rewards distributed per epoch
        let updated_params = Params {
            epoch_duration: 1u64.try_into().unwrap(),
            rewards_per_epoch: initial_params
                .rewards_per_epoch
                .into_inner()
                .checked_add(Uint128::from(1000u128))
                .unwrap()
                .try_into()
                .unwrap(),
            ..initial_params
        };

        let res = app.execute_contract(
            governance_address,
            contract_address.clone(),
            &ExecuteMsg::UpdatePoolParams {
                params: updated_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        // check the rewards pool reflects the new values
        let res: RewardsPool = app
            .wrap()
            .query_wasm_smart(
                contract_address.clone(),
                &QueryMsg::RewardsPool {
                    pool_id: pool_id.clone(),
                },
            )
            .unwrap();
        assert_eq!(
            res,
            RewardsPool {
                balance: Uint128::zero(),
                epoch_duration: updated_params.epoch_duration.into(),
                rewards_per_epoch: updated_params.rewards_per_epoch.into(),
                participation_threshold: updated_params.participation_threshold,
                current_epoch_num: 1u64.into(),
                last_distribution_epoch: None
            }
        );

        // now test distributing rewards for the previous epoch, when the params update occurred. The amount
        // of rewards distributed should reflect the updated params

        // need to change the block height, so we can claim rewards
        let old_height = app.block_info().height;
        app.set_block(BlockInfo {
            height: old_height + u64::from(updated_params.epoch_duration) * 2,
            ..app.block_info()
        });

        app.execute_contract(
            user.clone(),
            contract_address.clone(),
            &ExecuteMsg::AddRewards {
                pool_id: pool_id.clone(),
            },
            &coins(
                updated_params.rewards_per_epoch.into_inner().u128(),
                AXL_DENOMINATION,
            ),
        )
        .unwrap();

        app.execute_contract(
            user,
            contract_address.clone(),
            &ExecuteMsg::DistributeRewards {
                pool_id: PoolId {
                    chain_name: chain_name.clone(),
                    contract: pool_contract.to_string(),
                },
                epoch_count: None,
            },
            &[],
        )
        .unwrap();

        // verifier should have been sent the appropriate rewards
        let balance = app
            .wrap()
            .query_balance(verifier, AXL_DENOMINATION)
            .unwrap();
        assert_eq!(
            balance.amount,
            Uint128::from(updated_params.rewards_per_epoch)
        );
    }
}

#[cfg(test)]
mod reply_tests {
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{CosmosMsg, OwnedDeps, ReplyOn, SubMsgResult};
    use router_api::{chain_name, cosmos_addr};

    use super::*;
    use crate::msg::Params;
    use crate::state::{
        Epoch, ParamsSnapshot, RewardsPool, VERIFIER_PROXY_ADDRESSES,
    };

    const AXL: &str = "uaxl";
    const POOL_CONTRACT: &str = "pool_contract";
    const VERIFIER: &str = "verifier";
    const MOCK_CHAIN: &str = "mock-chain";

    type MockDeps = OwnedDeps<MockStorage, MockApi, MockQuerier>;

    fn test_pool_id() -> PoolId {
        PoolId {
            chain_name: chain_name!(MOCK_CHAIN),
            contract: cosmos_addr!(POOL_CONTRACT),
        }
    }

    fn setup_pool(initial_balance: u128) -> MockDeps {
        let mut deps = mock_dependencies();
        CONFIG
            .save(
                deps.as_mut().storage,
                &Config {
                    rewards_denom: AXL.into(),
                },
            )
            .unwrap();
        state::save_rewards_pool(
            deps.as_mut().storage,
            &RewardsPool {
                id: test_pool_id(),
                balance: cosmwasm_std::Uint128::from(initial_balance),
                params: ParamsSnapshot {
                    params: Params {
                        epoch_duration: 100u64.try_into().unwrap(),
                        rewards_per_epoch: cosmwasm_std::Uint128::from(100u128).try_into().unwrap(),
                        participation_threshold: (1, 2).try_into().unwrap(),
                    },
                    created_at: Epoch {
                        epoch_num: 0,
                        block_height_started: 0,
                    },
                },
            },
        )
        .unwrap();
        deps
    }

    fn make_reply(payload: &DistributionPayload) -> Reply {
        Reply {
            id: REWARDS_DISTRIBUTION_REPLY_ID,
            payload: to_json_binary(payload).unwrap(),
            gas_used: 0,
            result: SubMsgResult::Err("bank rejected".into()),
        }
    }

    #[test]
    fn proxy_send_failure_dispatches_fallback_to_verifier() {
        let mut deps = setup_pool(1000);
        let verifier = cosmos_addr!(VERIFIER);
        let proxy = cosmos_addr!("malicious_proxy");
        let amount = cosmwasm_std::Uint128::from(50u128);

        let payload = DistributionPayload {
            pool_id: test_pool_id(),
            verifier_address: verifier.clone(),
            proxy_address: Some(proxy.clone()),
            amount,
            destination: SendDestination::Proxy,
        };

        let res = reply(deps.as_mut(), mock_env(), make_reply(&payload)).unwrap();

        assert_eq!(res.messages.len(), 1);
        let sub = &res.messages[0];
        assert_eq!(sub.reply_on, ReplyOn::Error);
        assert_eq!(sub.id, REWARDS_DISTRIBUTION_REPLY_ID);

        match &sub.msg {
            CosmosMsg::Bank(BankMsg::Send {
                to_address,
                amount: coins,
            }) => {
                assert_eq!(to_address, verifier.as_str());
                assert_eq!(coins.len(), 1);
                assert_eq!(coins[0].amount, amount);
                assert_eq!(coins[0].denom, AXL);
            }
            _ => panic!("expected BankMsg::Send"),
        }

        let fallback: DistributionPayload = from_json(&sub.payload).unwrap();
        assert_eq!(fallback.destination, SendDestination::Verifier);
        assert_eq!(fallback.verifier_address, verifier);
        assert_eq!(fallback.proxy_address, Some(proxy));
        assert_eq!(fallback.amount, amount);
        assert_eq!(fallback.pool_id, test_pool_id());

        // pool balance unchanged: refund only happens after verifier-send fails
        let pool = state::load_rewards_pool(deps.as_ref().storage, test_pool_id()).unwrap();
        assert_eq!(pool.balance, cosmwasm_std::Uint128::from(1000u128));

        assert_eq!(res.events.len(), 1);
        assert_eq!(res.events[0].ty, "proxy_send_failed");
    }

    #[test]
    fn verifier_send_failure_after_fallback_refunds_pool() {
        let mut deps = setup_pool(1000);
        let verifier = cosmos_addr!(VERIFIER);
        let proxy = cosmos_addr!("malicious_proxy");
        let amount = cosmwasm_std::Uint128::from(50u128);

        let payload = DistributionPayload {
            pool_id: test_pool_id(),
            verifier_address: verifier,
            proxy_address: Some(proxy),
            amount,
            destination: SendDestination::Verifier,
        };

        let res = reply(deps.as_mut(), mock_env(), make_reply(&payload)).unwrap();
        assert!(res.messages.is_empty());

        let pool = state::load_rewards_pool(deps.as_ref().storage, test_pool_id()).unwrap();
        assert_eq!(pool.balance, cosmwasm_std::Uint128::from(1050u128));

        assert_eq!(res.events.len(), 1);
        assert_eq!(res.events[0].ty, "verifier_send_failed");
    }

    #[test]
    fn verifier_send_failure_no_proxy_refunds_pool() {
        let mut deps = setup_pool(1000);
        let verifier = cosmos_addr!(VERIFIER);
        let amount = cosmwasm_std::Uint128::from(50u128);

        let payload = DistributionPayload {
            pool_id: test_pool_id(),
            verifier_address: verifier,
            proxy_address: None,
            amount,
            destination: SendDestination::Verifier,
        };

        let res = reply(deps.as_mut(), mock_env(), make_reply(&payload)).unwrap();
        assert!(res.messages.is_empty());

        let pool = state::load_rewards_pool(deps.as_ref().storage, test_pool_id()).unwrap();
        assert_eq!(pool.balance, cosmwasm_std::Uint128::from(1050u128));

        assert_eq!(res.events.len(), 1);
        assert_eq!(res.events[0].ty, "verifier_send_failed");
    }

    #[test]
    fn malformed_payload_returns_error() {
        let mut deps = setup_pool(1000);
        let reply_msg = Reply {
            id: REWARDS_DISTRIBUTION_REPLY_ID,
            payload: Binary::new(b"not valid json".to_vec()),
            gas_used: 0,
            result: SubMsgResult::Err("ignored".into()),
        };
        assert!(reply(deps.as_mut(), mock_env(), reply_msg).is_err());
    }

    #[test]
    #[should_panic(expected = "unknown reply ID")]
    fn unknown_reply_id_panics() {
        let mut deps = setup_pool(1000);
        let reply_msg = Reply {
            id: 999,
            payload: Binary::default(),
            gas_used: 0,
            result: SubMsgResult::Err("ignored".into()),
        };
        let _ = reply(deps.as_mut(), mock_env(), reply_msg);
    }

    #[test]
    fn distribute_rewards_dispatches_reply_on_error_submsg_for_proxy() {
        let mut deps = setup_pool(1000);
        let verifier = cosmos_addr!(VERIFIER);
        let proxy = cosmos_addr!("proxy");

        execute::record_participation(
            deps.as_mut().storage,
            "event-1".to_string().try_into().unwrap(),
            verifier.clone(),
            test_pool_id(),
            0,
        )
        .unwrap();
        VERIFIER_PROXY_ADDRESSES
            .save(deps.as_mut().storage, verifier.clone(), &proxy)
            .unwrap();

        let mut env = mock_env();
        env.block.height = 200;

        let res = execute(
            deps.as_mut(),
            env,
            message_info(&cosmos_addr!("caller"), &[]),
            ExecuteMsg::DistributeRewards {
                pool_id: crate::msg::PoolId {
                    chain_name: chain_name!(MOCK_CHAIN),
                    contract: cosmos_addr!(POOL_CONTRACT).to_string(),
                },
                epoch_count: None,
            },
        )
        .unwrap();

        assert_eq!(res.messages.len(), 1);
        let sub = &res.messages[0];
        assert_eq!(sub.reply_on, ReplyOn::Error);
        assert_eq!(sub.id, REWARDS_DISTRIBUTION_REPLY_ID);

        match &sub.msg {
            CosmosMsg::Bank(BankMsg::Send {
                to_address,
                amount: coins,
            }) => {
                assert_eq!(to_address, proxy.as_str());
                assert_eq!(coins[0].denom, AXL);
                assert_eq!(coins[0].amount, cosmwasm_std::Uint128::from(100u128));
            }
            _ => panic!("expected BankMsg::Send"),
        }

        let payload: DistributionPayload = from_json(&sub.payload).unwrap();
        assert_eq!(payload.destination, SendDestination::Proxy);
        assert_eq!(payload.verifier_address, verifier);
        assert_eq!(payload.proxy_address, Some(proxy));
        assert_eq!(payload.amount, cosmwasm_std::Uint128::from(100u128));
    }

    #[test]
    fn distribute_rewards_dispatches_reply_on_error_submsg_without_proxy() {
        let mut deps = setup_pool(1000);
        let verifier = cosmos_addr!(VERIFIER);

        execute::record_participation(
            deps.as_mut().storage,
            "event-1".to_string().try_into().unwrap(),
            verifier.clone(),
            test_pool_id(),
            0,
        )
        .unwrap();

        let mut env = mock_env();
        env.block.height = 200;

        let res = execute(
            deps.as_mut(),
            env,
            message_info(&cosmos_addr!("caller"), &[]),
            ExecuteMsg::DistributeRewards {
                pool_id: crate::msg::PoolId {
                    chain_name: chain_name!(MOCK_CHAIN),
                    contract: cosmos_addr!(POOL_CONTRACT).to_string(),
                },
                epoch_count: None,
            },
        )
        .unwrap();

        assert_eq!(res.messages.len(), 1);
        let sub = &res.messages[0];
        assert_eq!(sub.reply_on, ReplyOn::Error);

        match &sub.msg {
            CosmosMsg::Bank(BankMsg::Send { to_address, .. }) => {
                assert_eq!(to_address, verifier.as_str());
            }
            _ => panic!("expected BankMsg::Send"),
        }

        let payload: DistributionPayload = from_json(&sub.payload).unwrap();
        assert_eq!(payload.destination, SendDestination::Verifier);
        assert_eq!(payload.proxy_address, None);
        assert_eq!(payload.verifier_address, verifier);
    }
}
