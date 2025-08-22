use std::marker::PhantomData;

use axelar_core_std::nexus;
use axelar_core_std::nexus::query::IsChainRegisteredResponse;
use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::error::ContractError;
use cosmwasm_std::testing::{message_info, mock_env, MockApi, MockQuerier, MockStorage};
use cosmwasm_std::{
    from_json, to_json_binary, DepsMut, HexBinary, MemoryStorage, OwnedDeps, Response,
    SystemResult, WasmQuery,
};
use interchain_token_service::contract;
use interchain_token_service::msg::{self, ExecuteMsg, SupplyModifier, TruncationConfig};
use interchain_token_service::shared::NumBits;
use interchain_token_service_std::{HubMessage, TokenId};
use its_abi_translator::abi::{hub_message_abi_decode, hub_message_abi_encode};
use its_msg_translator_api::QueryMsg;
use router_api::{chain_name, cosmos_addr, cosmos_address, Address, ChainNameRaw, CrossChainId};

use super::{instantiate_contract, TestMessage};
use crate::utils::params;

pub fn execute(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    payload: HexBinary,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&cosmos_addr!(params::GATEWAY), &[]),
        ExecuteMsg::Execute(axelarnet_gateway::AxelarExecutableMsg {
            cc_id,
            source_address,
            payload,
        }),
    )
}

pub fn execute_hub_message(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    message: HubMessage,
) -> Result<Response, ContractError> {
    execute(deps, cc_id, source_address, hub_message_abi_encode(message))
}

pub fn make_deps() -> OwnedDeps<MemoryStorage, MockApi, MockQuerier<AxelarQueryMsg>> {
    let addr = cosmos_addr!(params::GATEWAY);
    let translation_contract_addr = cosmos_addr!(params::TRANSLATION_CONTRACT).to_string();
    let mut deps = OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: MockQuerier::<AxelarQueryMsg>::new(&[]),
        custom_query_type: PhantomData,
    };

    let mut querier = MockQuerier::<AxelarQueryMsg>::new(&[]);
    querier.update_wasm(move |msg| match msg {
        WasmQuery::Smart { contract_addr, msg } if contract_addr == &addr.to_string() => {
            let msg: axelarnet_gateway::msg::QueryMsg =
                from_json::<axelarnet_gateway::msg::QueryMsg>(msg).unwrap();
            match msg {
                axelarnet_gateway::msg::QueryMsg::ChainName => {
                    Ok(to_json_binary(&chain_name!(params::AXELAR)).into()).into()
                }
                _ => panic!("unsupported query"),
            }
        }
        WasmQuery::Smart { contract_addr, msg } if *contract_addr == translation_contract_addr => {
            // Handle translation contract queries
            let query_msg = from_json::<QueryMsg>(msg).unwrap();
            match query_msg {
                QueryMsg::FromBytes { payload } => {
                    // Use the actual translation logic
                    match hub_message_abi_decode(payload) {
                        Ok(hub_message) => Ok(to_json_binary(&hub_message).into()).into(),
                        Err(_) => SystemResult::Err(cosmwasm_std::SystemError::InvalidRequest {
                            error: "Translation failed".to_string(),
                            request: Default::default(),
                        }),
                    }
                }
                QueryMsg::ToBytes { message } => {
                    // Use the actual translation logic
                    let payload = hub_message_abi_encode(message);
                    Ok(to_json_binary(&payload).into()).into()
                }
            }
        }
        _ => panic!("unexpected query: {:?}", msg),
    });
    querier = querier.with_custom_handler(|msg| match msg {
        AxelarQueryMsg::Nexus(nexus::query::QueryMsg::IsChainRegistered { chain }) => {
            Ok(to_json_binary(
                &(IsChainRegisteredResponse {
                    is_registered: chain == "ethereum",
                }),
            )
            .into())
            .into()
        }
        _ => panic!("unsupported query"),
    });

    deps.querier = querier;
    deps
}

pub fn register_chain(
    deps: DepsMut,
    chain: ChainNameRaw,
    its_edge_contract: Address,
    max_uint_bits: NumBits,
    max_decimals_when_truncating: u8,
) -> Result<Response, ContractError> {
    register_chains(
        deps,
        vec![msg::ChainConfig {
            chain,
            its_edge_contract,
            truncation: TruncationConfig {
                max_uint_bits,
                max_decimals_when_truncating,
            },
            msg_translator: cosmos_address!(params::TRANSLATION_CONTRACT),
        }],
    )
}

pub fn register_chains(
    deps: DepsMut,
    chains: Vec<msg::ChainConfig>,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&cosmos_addr!(params::GOVERNANCE), &[]),
        ExecuteMsg::RegisterChains { chains },
    )
}

pub fn register_p2p_token_instance(
    deps: DepsMut,
    sender: &str,
    token_id: TokenId,
    origin_chain: ChainNameRaw,
    chain: ChainNameRaw,
    decimals: u8,
    supply: msg::TokenSupply,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&MockApi::default().addr_make(sender), &[]),
        ExecuteMsg::RegisterP2pTokenInstance {
            chain,
            origin_chain,
            token_id,
            decimals,
            supply,
        },
    )
}

pub fn update_chain(
    deps: DepsMut,
    chain: ChainNameRaw,
    its_edge_contract: Address,
    max_uint_bits: NumBits,
    max_decimals_when_truncating: u8,
) -> Result<Response, ContractError> {
    update_chains(
        deps,
        vec![msg::ChainConfig {
            chain,
            its_edge_contract,
            truncation: TruncationConfig {
                max_uint_bits,
                max_decimals_when_truncating,
            },
            msg_translator: cosmos_address!(params::TRANSLATION_CONTRACT),
        }],
    )
}

pub fn update_chains(
    deps: DepsMut,
    chains: Vec<msg::ChainConfig>,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&cosmos_addr!(params::GOVERNANCE), &[]),
        ExecuteMsg::UpdateChains { chains },
    )
}

pub fn freeze_chain(deps: DepsMut, chain: ChainNameRaw) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&cosmos_addr!(params::GOVERNANCE), &[]),
        ExecuteMsg::FreezeChain { chain },
    )
}

pub fn disable_contract_execution(deps: DepsMut) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&cosmos_addr!(params::GOVERNANCE), &[]),
        ExecuteMsg::DisableExecution,
    )
}

pub fn modify_supply(
    deps: DepsMut,
    chain: ChainNameRaw,
    supply_modifier: SupplyModifier,
    token_id: TokenId,
    sender: &str,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        message_info(&MockApi::default().addr_make(sender), &[]),
        ExecuteMsg::ModifySupply {
            chain,
            token_id,
            supply_modifier,
        },
    )
}

pub fn register_chain_with_translation(
    deps: DepsMut,
    chain: ChainNameRaw,
    its_edge_contract: Address,
    max_uint_bits: NumBits,
    max_decimals_when_truncating: u8,
    msg_translator: Address,
) -> Result<Response, ContractError> {
    register_chains(
        deps,
        vec![msg::ChainConfig {
            chain,
            its_edge_contract,
            truncation: TruncationConfig {
                max_uint_bits,
                max_decimals_when_truncating,
            },
            msg_translator,
        }],
    )
}

pub fn update_chain_with_translation(
    deps: DepsMut,
    chain: ChainNameRaw,
    its_edge_contract: Address,
    max_uint_bits: NumBits,
    max_decimals_when_truncating: u8,
    msg_translator: Address,
) -> Result<Response, ContractError> {
    update_chains(
        deps,
        vec![msg::ChainConfig {
            chain,
            its_edge_contract,
            truncation: TruncationConfig {
                max_uint_bits,
                max_decimals_when_truncating,
            },
            msg_translator,
        }],
    )
}

pub fn setup_multiple_chains(
    configs: Vec<(ChainNameRaw, Address, u32, u8)>,
) -> (
    OwnedDeps<MemoryStorage, MockApi, MockQuerier<AxelarQueryMsg>>,
    TestMessage,
) {
    let mut deps = make_deps();
    instantiate_contract(deps.as_mut()).unwrap();
    for (chain_name, its_address, max_uint, target_decimals) in configs {
        register_chain(
            deps.as_mut(),
            chain_name,
            its_address,
            max_uint.try_into().unwrap(),
            target_decimals,
        )
        .unwrap();
    }
    (deps, TestMessage::dummy())
}

pub fn setup_with_chain_configs(
    source_max_uint: u32,
    source_max_target_decimals: u8,
    destination_max_uint: u32,
    destination_max_target_decimals: u8,
) -> (
    OwnedDeps<MemoryStorage, MockApi, MockQuerier<AxelarQueryMsg>>,
    TestMessage,
) {
    let mut deps = make_deps();
    instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        source_its_chain,
        source_its_contract,
        destination_its_chain,
        destination_its_contract,
        ..
    } = TestMessage::dummy();

    register_chain(
        deps.as_mut(),
        source_its_chain,
        source_its_contract,
        source_max_uint.try_into().unwrap(),
        source_max_target_decimals,
    )
    .unwrap();

    register_chain(
        deps.as_mut(),
        destination_its_chain,
        destination_its_contract,
        destination_max_uint.try_into().unwrap(),
        destination_max_target_decimals,
    )
    .unwrap();

    (deps, TestMessage::dummy())
}

pub fn setup() -> (
    OwnedDeps<MemoryStorage, MockApi, MockQuerier<AxelarQueryMsg>>,
    TestMessage,
) {
    let mut deps = make_deps();
    instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        source_its_chain,
        source_its_contract,
        destination_its_chain,
        destination_its_contract,
        ..
    } = TestMessage::dummy();

    register_chain(
        deps.as_mut(),
        source_its_chain.clone(),
        source_its_contract.clone(),
        256.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();
    register_chain(
        deps.as_mut(),
        destination_its_chain.clone(),
        destination_its_contract.clone(),
        256.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();

    (deps, TestMessage::dummy())
}
