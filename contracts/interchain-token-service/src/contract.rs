use std::fmt::Debug;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::token::GetToken;
use axelar_wasm_std::{address, permission_control, FnExt, IntoContractError};
use axelarnet_gateway::AxelarExecutableMsg;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, Storage};
use error_stack::{Report, ResultExt};

use crate::events::Event;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state;
use crate::state::Config;

mod execute;
mod query;

pub use execute::Error as ExecuteError;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to execute a cross-chain message")]
    Execute,
    #[error("failed to register an its edge contract")]
    RegisterItsContract,
    #[error("failed to deregsiter an its edge contract")]
    DeregisterItsContract,
    #[error("failed to register gateway token")]
    RegisterGatewayToken,
    #[error("too many coins attached. Execute accepts zero or one coins")]
    TooManyCoins,
    #[error("failed to query its address")]
    QueryItsContract,
    #[error("failed to query all its addresses")]
    QueryAllItsContracts,
    #[error("failed to query gateway tokens")]
    QueryGatewayTokens,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: Empty) -> Result<Response, ContractError> {
    // Implement migration logic if needed

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _: Env,
    _: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = address::validate_cosmwasm_address(deps.api, &msg.admin_address)?;
    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;

    permission_control::set_admin(deps.storage, &admin)?;
    permission_control::set_governance(deps.storage, &governance)?;

    let axelarnet_gateway =
        address::validate_cosmwasm_address(deps.api, &msg.axelarnet_gateway_address)?;

    state::save_config(deps.storage, &Config { axelarnet_gateway })?;

    for (chain, address) in msg.its_contracts.iter() {
        state::save_its_contract(deps.storage, chain, address)?;
    }

    Ok(Response::new().add_events(
        msg.its_contracts
            .into_iter()
            .map(|(chain, address)| Event::ItsContractRegistered { chain, address }.into()),
    ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender, match_gateway)? {
        ExecuteMsg::Execute(AxelarExecutableMsg {
            cc_id,
            source_address,
            payload,
        }) => {
            let coin = info.single_token()?;
            execute::execute_message(deps, cc_id, source_address, payload, coin)
                .change_context(Error::Execute)
        }
        ExecuteMsg::RegisterItsContract { chain, address } => {
            execute::register_its_contract(deps, chain, address)
                .change_context(Error::RegisterItsContract)
        }
        ExecuteMsg::DeregisterItsContract { chain } => {
            execute::deregister_its_contract(deps, chain)
                .change_context(Error::DeregisterItsContract)
        }
        ExecuteMsg::RegisterGatewayToken {
            denom,
            source_chain,
        } => execute::register_gateway_token(deps, denom, source_chain)
            .change_context(Error::RegisterGatewayToken),
    }?
    .then(Ok)
}

fn match_gateway(storage: &dyn Storage, _: &ExecuteMsg) -> Result<Addr, Report<Error>> {
    Ok(state::load_config(storage).axelarnet_gateway)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::ItsContract { chain } => {
            query::its_contracts(deps, chain).change_context(Error::QueryItsContract)
        }
        QueryMsg::AllItsContracts => {
            query::all_its_contracts(deps).change_context(Error::QueryAllItsContracts)
        }
        QueryMsg::GatewayTokens => {
            query::gateway_tokens(deps).change_context(Error::QueryGatewayTokens)
        }
    }?
    .then(Ok)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use assert_ok::assert_ok;
    use axelar_core_std::nexus;
    use axelar_core_std::nexus::query::IsChainRegisteredResponse;
    use axelar_core_std::query::AxelarQueryMsg;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::nonempty;
    use axelar_wasm_std::response::inspect_response_msg;
    use axelarnet_gateway::AxelarExecutableMsg;
    use cosmwasm_std::testing::{mock_env, mock_info, MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{
        from_json, to_json_binary, Coin, CosmosMsg, HexBinary, MemoryStorage, OwnedDeps, Uint128,
        WasmMsg, WasmQuery,
    };
    use router_api::{ChainName, ChainNameRaw, CrossChainId};

    use super::{execute, instantiate};
    use crate::contract::execute::gateway_token_id;
    use crate::contract::query;
    use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
    use crate::{HubMessage, Message, TokenId};
    const GOVERNANCE_ADDRESS: &str = "governance";
    const ADMIN_ADDRESS: &str = "admin";
    const AXELARNET_GATEWAY_ADDRESS: &str = "axelarnet-gateway";
    const CORE_CHAIN: &str = "ethereum";
    const AMPLIFIER_CHAIN: &str = "solana";
    const AXELAR_CHAIN_NAME: &str = "axelar";

    #[test]
    fn register_gateway_token_should_register_denom_and_token_id() {
        let mut deps = setup();
        let denom = "uaxl";
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterGatewayToken {
                denom: denom.try_into().unwrap(),
                source_chain: ChainNameRaw::try_from("axelar").unwrap(),
            },
        );
        assert!(res.is_ok());

        let tokens: HashMap<nonempty::String, TokenId> =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::GatewayTokens).unwrap()).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(
            tokens,
            HashMap::from([(
                denom.try_into().unwrap(),
                gateway_token_id(&deps.as_mut(), denom).unwrap()
            )])
        );
    }

    /// Tests that a token can be attached to an ITS message, escrowed in the contract, and then subsequently
    /// unlocked and sent back at a later time
    #[test]
    fn send_token_from_core_and_back() {
        let mut deps = setup();
        let denom = "eth";
        let source_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let destination_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();

        let its_address = "68d30f47F19c07bCCEf4Ac7FAE2Dc12FCa3e0dC9";
        let source_address =
            HexBinary::from_hex("4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();

        assert_ok!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterGatewayToken {
                denom: denom.try_into().unwrap(),
                source_chain: source_chain.clone(),
            },
        ));

        assert_ok!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterItsContract {
                chain: source_chain.clone(),
                address: its_address.to_string().try_into().unwrap()
            }
        ));

        assert_ok!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE_ADDRESS, &[]),
            ExecuteMsg::RegisterItsContract {
                chain: destination_chain.clone(),
                address: its_address.to_string().try_into().unwrap()
            }
        ));

        let coin = Coin {
            denom: denom.to_string(),
            amount: Uint128::new(100u128),
        };

        let token_id = gateway_token_id(&deps.as_mut(), denom).unwrap();
        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: token_id.clone(),
                source_address: source_address.clone().try_into().unwrap(),
                destination_address: HexBinary::from_hex(its_address).unwrap().try_into().unwrap(),
                amount: coin.amount.into(),
                data: None,
            },
        };

        assert_ok!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(AXELARNET_GATEWAY_ADDRESS, &[coin.clone()]),
            ExecuteMsg::Execute(AxelarExecutableMsg {
                cc_id: CrossChainId {
                    source_chain: source_chain.clone(),
                    message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                        .to_string()
                        .try_into()
                        .unwrap(),
                },
                source_address: its_address.to_string().try_into().unwrap(),
                payload: msg.abi_encode(),
            })
        ));

        let msg = HubMessage::SendToHub {
            destination_chain: source_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: token_id.clone(),
                source_address: source_address.clone().try_into().unwrap(),
                destination_address: HexBinary::from_hex(its_address).unwrap().try_into().unwrap(),
                amount: coin.amount.into(),
                data: None,
            },
        };

        let res = assert_ok!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info(AXELARNET_GATEWAY_ADDRESS, &[]),
            ExecuteMsg::Execute(AxelarExecutableMsg {
                cc_id: CrossChainId {
                    source_chain: destination_chain.clone(),
                    message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                        .to_string()
                        .try_into()
                        .unwrap(),
                },
                source_address: its_address.to_string().try_into().unwrap(),
                payload: msg.abi_encode(),
            })
        ));
        let _msg: axelarnet_gateway::msg::ExecuteMsg =
            assert_ok!(inspect_response_msg(res.clone()));

        match &res.messages.first().unwrap().msg {
            CosmosMsg::Wasm(WasmMsg::Execute { funds, .. }) => {
                assert_eq!(funds.len(), 1);
                assert_eq!(funds.first().unwrap(), &coin);
            }
            _ => panic!("incorrect msg type"),
        };
    }

    fn make_deps() -> OwnedDeps<MemoryStorage, MockApi, MockQuerier<AxelarQueryMsg>> {
        let mut deps = OwnedDeps {
            storage: MockStorage::default(),
            api: MockApi::default(),
            querier: MockQuerier::<AxelarQueryMsg>::new(&[]),
            custom_query_type: PhantomData,
        };

        let mut querier = MockQuerier::<AxelarQueryMsg>::new(&[]);
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == AXELARNET_GATEWAY_ADDRESS =>
            {
                let msg = from_json::<axelarnet_gateway::msg::QueryMsg>(msg).unwrap();
                match msg {
                    axelarnet_gateway::msg::QueryMsg::ChainName {} => {
                        Ok(to_json_binary(&ChainName::try_from(AXELAR_CHAIN_NAME).unwrap()).into())
                            .into()
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
                        is_registered: chain == CORE_CHAIN,
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

    fn setup() -> OwnedDeps<MemoryStorage, MockApi, MockQuerier<AxelarQueryMsg>> {
        let mut deps = make_deps();

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("instantiator", &[]),
            InstantiateMsg {
                governance_address: GOVERNANCE_ADDRESS.to_string(),
                admin_address: ADMIN_ADDRESS.to_string(),
                axelarnet_gateway_address: AXELARNET_GATEWAY_ADDRESS.to_string(),
                its_contracts: HashMap::new(),
            },
        )
        .unwrap();

        deps
    }
}
