use std::marker::PhantomData;

use axelar_core_std::nexus;
use axelar_core_std::nexus::query::IsChainRegisteredResponse;
use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::nonempty;
use cosmwasm_std::testing::{mock_env, mock_info, MockApi, MockQuerier, MockStorage};
use cosmwasm_std::{
    from_json, to_json_binary, Addr, DepsMut, HexBinary, MemoryStorage, OwnedDeps, Response,
    Uint256, WasmQuery,
};
use interchain_token_service::msg::{self, ExecuteMsg};
use interchain_token_service::{contract, HubMessage};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

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
        mock_info(params::GATEWAY, &[]),
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
    execute(deps, cc_id, source_address, message.abi_encode())
}

pub fn make_deps() -> OwnedDeps<MemoryStorage, MockApi, MockQuerier<AxelarQueryMsg>> {
    let addr = Addr::unchecked(params::GATEWAY);
    let mut deps = OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: MockQuerier::<AxelarQueryMsg>::new(&[]),
        custom_query_type: PhantomData,
    };

    let mut querier = MockQuerier::<AxelarQueryMsg>::new(&[]);
    querier.update_wasm(move |msg| match msg {
        WasmQuery::Smart { contract_addr, msg } if contract_addr == &addr.to_string() => {
            let msg = from_json::<axelarnet_gateway::msg::QueryMsg>(msg).unwrap();
            match msg {
                axelarnet_gateway::msg::QueryMsg::ChainName {} => {
                    Ok(to_json_binary(&ChainName::try_from("axelar").unwrap()).into()).into()
                }
                _ => panic!("unsupported query"),
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
    max_uint: nonempty::Uint256,
    max_target_decimals: u8,
) -> Result<Response, ContractError> {
    register_chains(
        deps,
        vec![msg::ChainConfig {
            chain,
            its_edge_contract,
            max_uint,
            max_target_decimals,
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
        mock_info(params::GOVERNANCE, &[]),
        ExecuteMsg::RegisterChains { chains },
    )
}

pub fn update_chain(
    deps: DepsMut,
    chain: ChainNameRaw,
    its_edge_contract: Address,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info(params::GOVERNANCE, &[]),
        ExecuteMsg::UpdateChain {
            chain,
            its_edge_contract,
        },
    )
}

pub fn setup_with_chain_configs(
    source_max_uint: nonempty::Uint256,
    source_max_target_decimals: u8,
    destination_max_uint: nonempty::Uint256,
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
        source_max_uint,
        source_max_target_decimals,
    )
    .unwrap();

    register_chain(
        deps.as_mut(),
        destination_its_chain,
        destination_its_contract,
        destination_max_uint,
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
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();
    register_chain(
        deps.as_mut(),
        destination_its_chain.clone(),
        destination_its_contract.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();

    (deps, TestMessage::dummy())
}
