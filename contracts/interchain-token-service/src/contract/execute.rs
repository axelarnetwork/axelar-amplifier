use axelar_wasm_std::{nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};
use sha3::{Digest, Keccak256};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{self, load_config, load_its_contract, may_load_its_contract};
use crate::{Message, TokenId};

// this is just keccak256("its-interchain-token-id-gateway")
const GATEWAY_TOKEN_PREFIX: [u8; 32] = [
    106, 80, 188, 250, 12, 170, 167, 223, 94, 185, 52, 185, 146, 147, 21, 23, 145, 36, 97, 146,
    215, 72, 32, 167, 6, 16, 83, 155, 176, 213, 112, 44,
];

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("unknown chain {0}")]
    UnknownChain(ChainNameRaw),
    #[error("unknown its address {0}")]
    UnknownItsContract(Address),
    #[error("failed to decode payload")]
    InvalidPayload,
    #[error("invalid message type")]
    InvalidMessageType,
    #[error("failed to register its contract for chain {0}")]
    FailedItsContractRegistration(ChainNameRaw),
    #[error("failed to deregister its contract for chain {0}")]
    FailedItsContractDeregistration(ChainNameRaw),
    #[error("failed to register gateway token")]
    FailedGatewayTokenRegistration,
    #[error("failed to generate token id")]
    FailedTokenIdGeneration,
    #[error("failed to query evm module")]
    EvmQueryError,
    #[error("failed to query axelarnet gateway")]
    AxelarnetGatewayQueryError,
    #[error("token is not external")]
    TokenNotExternal,
    #[error("decimals overflowed u8")]
    TooManyDecimals,
    #[error("no its contract registered for chain {0}")]
    NoItsContractRegistered(ChainNameRaw),
    #[error("storage error")]
    StorageError,
}

/// Executes an incoming ITS message.
///
/// This function handles the execution of ITS (Interchain Token Service) messages received from
/// its sources. It verifies the source address, decodes the message, applies balance tracking,
/// and forwards the message to the destination chain.
pub fn execute_message(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    ensure_its_source_address(deps.storage, &cc_id.source_chain, &source_address)?;

    match HubMessage::abi_decode(&payload).change_context(Error::InvalidPayload)? {
        HubMessage::SendToHub {
            destination_chain,
            message,
        } => {
            let destination_address = load_its_contract(deps.storage, &destination_chain)
                .change_context_lazy(|| Error::UnknownChain(destination_chain.clone()))?;

            let destination_payload = HubMessage::ReceiveFromHub {
                source_chain: cc_id.source_chain.clone(),
                message: message.clone(),
            }
            .abi_encode();

            Ok(send_to_destination(
                deps.storage,
                deps.querier,
                destination_chain.clone(),
                destination_address,
                destination_payload,
            )?
            .add_event(
                Event::MessageReceived {
                    cc_id,
                    destination_chain,
                    message,
                }
                .into(),
            ))
        }
        _ => bail!(Error::InvalidMessageType),
    }
}

fn normalize(chain: &ChainNameRaw) -> ChainName {
    ChainName::try_from(chain.as_ref()).expect("invalid chain name")
}

/// Ensures that the source address of the cross-chain message is the registered ITS contract for the source chain.
fn ensure_its_source_address(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    source_address: &Address,
) -> Result<(), Error> {
    let source_its_contract = load_its_contract(storage, source_chain)
        .change_context_lazy(|| Error::UnknownChain(source_chain.clone()))?;

    ensure!(
        source_address == &source_its_contract,
        Error::UnknownItsContract(source_address.clone())
    );

    Ok(())
}

fn send_to_destination(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: ChainNameRaw,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let config = load_config(storage);

    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(querier, &config.axelarnet_gateway).into();

    let call_contract_msg =
        gateway.call_contract(normalize(&destination_chain), destination_address, payload);

    Ok(Response::new().add_message(call_contract_msg))
}

pub fn register_its_contract(
    deps: DepsMut,
    chain: ChainNameRaw,
    address: Address,
) -> Result<Response, Error> {
    state::save_its_contract(deps.storage, &chain, &address)
        .change_context_lazy(|| Error::FailedItsContractRegistration(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsContractRegistered { chain, address }.into()))
}

pub fn deregister_its_contract(deps: DepsMut, chain: ChainNameRaw) -> Result<Response, Error> {
    state::remove_its_contract(deps.storage, &chain)
        .change_context_lazy(|| Error::FailedItsContractDeregistration(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsContractDeregistered { chain }.into()))
}

pub fn register_gateway_token(
    deps: DepsMut,
    denom: nonempty::String,
    _chain: ChainNameRaw,
) -> Result<Response, Error> {
    let token_id = gateway_token_id(&deps, &denom)?;
    state::save_gateway_token_denom(deps.storage, token_id, denom)
        .change_context(Error::FailedGatewayTokenRegistration)?;
    Ok(Response::new())
}

pub fn deploy_gateway_token(
    deps: DepsMut,
    denom: nonempty::String,
    source_chain: ChainNameRaw,
    destination_chain: ChainNameRaw,
) -> Result<Response, Error> {
    let client: axelar_core_std::evm::Client = client::CosmosClient::new(deps.querier).into();
    let token_info = client
        .token_info(&source_chain, denom.clone())
        .change_context(Error::EvmQueryError)?;
    if !token_info.is_external {
        bail!(Error::TokenNotExternal);
    }
    let token_id = gateway_token_id(&deps, &denom)?;
    let msg = Message::DeployInterchainToken {
        token_id,
        name: token_info.details.token_name,
        symbol: token_info.details.symbol,
        decimals: u8::try_from(token_info.details.decimals).change_context(Error::TooManyDecimals)?,
        minter: HexBinary::from([]),
    };
    let config = state::load_config(deps.storage);
    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(deps.querier, &config.axelarnet_gateway).into();
    let chain_name = gateway
        .chain_name()
        .change_context(Error::AxelarnetGatewayQueryError)?;

    let destination_payload = HubMessage::ReceiveFromHub {
        source_chain: chain_name.into(),
        message: msg.clone(),
    }
    .abi_encode();
    let its_contract = may_load_its_contract(deps.storage, &destination_chain)
        .change_context(Error::StorageError)?
        .ok_or(Error::NoItsContractRegistered(destination_chain.clone()))?;

    send_to_destination(
        deps.storage,
        deps.querier,
        destination_chain.clone(),
        its_contract,
        destination_payload,
    )
}

pub fn gateway_token_id(deps: &DepsMut, denom: &str) -> Result<TokenId, Error> {
    let config = state::load_config(deps.storage);
    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(deps.querier, &config.axelarnet_gateway).into();
    let chain_name = gateway
        .chain_name()
        .change_context(Error::FailedTokenIdGeneration)?;
    let chain_name_hash: [u8; 32] = Keccak256::digest(chain_name.to_string().as_bytes()).into();

    Keccak256::digest([&GATEWAY_TOKEN_PREFIX, &chain_name_hash, denom.as_bytes()].concat())
        .then(<[u8; 32]>::from)
        .then(TokenId::new)
        .then(Ok)
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use assert_ok::assert_ok;
    use axelar_core_std::evm;
    use axelar_core_std::evm::query::{TokenDetails, TokenInfoResponse};
    use axelar_core_std::query::AxelarQueryMsg;
    use axelar_wasm_std::assert_err_contains;
    use axelar_wasm_std::response::inspect_response_msg;
    use axelarnet_gateway::msg::QueryMsg;
    use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, HexBinary, MemoryStorage, OwnedDeps, Uint256, WasmQuery,
    };
    use router_api::{ChainName, ChainNameRaw};

    use super::{deploy_gateway_token, gateway_token_id, register_gateway_token, Error};
    use crate::contract::execute::register_its_contract;
    use crate::state::{self, Config};
    use crate::{HubMessage, Message};

    const CORE_CHAIN: &str = "ethereum";
    const AMPLIFIER_CHAIN: &str = "solana";
    const GATEWAY_TOKEN_DENOM: &str = "eth";
    const ITS_ADDRESS: &str = "68d30f47F19c07bCCEf4Ac7FAE2Dc12FCa3e0dC9";
    const AXELAR_CHAIN_NAME: &str = "axelar";
    const GATEWAY_TOKEN_DECIMALS: u8 = 8;
    const GATEWAY_TOKEN_ASSET_NAME: &str = "ethereum";

    #[test]
    fn gateway_token_id_should_be_idempotent() {
        let mut deps = init();
        let denom = "uaxl";
        let token_id = assert_ok!(gateway_token_id(&deps.as_mut(), denom));
        let token_id_2 = assert_ok!(gateway_token_id(&deps.as_mut(), denom));
        assert_eq!(token_id, token_id_2);
    }

    #[test]
    fn gateway_token_id_should_differ_for_different_denoms() {
        let mut deps = init();
        let axl_denom = "uaxl";
        let eth_denom = "eth";
        let token_id_axl = assert_ok!(gateway_token_id(&deps.as_mut(), axl_denom));
        let token_id_eth = assert_ok!(gateway_token_id(&deps.as_mut(), eth_denom));
        assert_ne!(token_id_axl, token_id_eth);
    }

    #[test]
    fn gateway_token_id_should_not_change() {
        let mut deps = init();
        let denom = "uaxl";
        let token_id = assert_ok!(gateway_token_id(&deps.as_mut(), denom));
        goldie::assert_json!(token_id);
    }

    #[test]
    fn register_token_id_should_not_overwrite() {
        let mut deps = init();
        let denom = "uaxl";
        let chain = ChainNameRaw::try_from("ethereum").unwrap();
        assert_ok!(register_gateway_token(
            deps.as_mut(),
            denom.try_into().unwrap(),
            chain.clone()
        ));
        // calling again should fail
        assert_err_contains!(
            register_gateway_token(deps.as_mut(), denom.try_into().unwrap(), chain),
            Error,
            Error::FailedGatewayTokenRegistration
        );
    }

    #[test]
    fn deploy_gateway_token_should_deploy() {
        let mut deps = init();
        let denom = GATEWAY_TOKEN_DENOM.to_string().try_into().unwrap();
        let chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let target_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        assert_ok!(register_its_contract(
            deps.as_mut(),
            target_chain.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap()
        ));
        let res = assert_ok!(deploy_gateway_token(
            deps.as_mut(),
            denom,
            chain,
            target_chain.clone()
        ));
        let msg: axelarnet_gateway::msg::ExecuteMsg = assert_ok!(inspect_response_msg(res));
        match msg {
            axelarnet_gateway::msg::ExecuteMsg::CallContract {
                destination_chain,
                destination_address,
                payload,
            } => {
                assert_eq!(
                    destination_chain,
                    ChainName::try_from(target_chain.as_ref()).unwrap()
                );
                assert_eq!(
                    destination_address,
                    ITS_ADDRESS.to_string().try_into().unwrap()
                );
                let decoded = assert_ok!(HubMessage::abi_decode(&payload));
                match decoded {
                    HubMessage::ReceiveFromHub {
                        source_chain,
                        message,
                    } => {
                        assert_eq!(
                            source_chain,
                            ChainNameRaw::try_from(AXELAR_CHAIN_NAME).unwrap()
                        );
                        match message {
                            Message::DeployInterchainToken {
                                token_id,
                                name,
                                symbol,
                                decimals,
                                minter,
                            } => {
                                assert_eq!(name, GATEWAY_TOKEN_ASSET_NAME);
                                assert_eq!(symbol, GATEWAY_TOKEN_DENOM);
                                assert_eq!(decimals, GATEWAY_TOKEN_DECIMALS);
                                assert_eq!(
                                    gateway_token_id(&deps.as_mut(), GATEWAY_TOKEN_DENOM).unwrap(),
                                    token_id
                                );
                                assert_eq!(minter, HexBinary::from([]));
                            }
                            _ => assert!(false),
                        }
                    }
                    _ => assert!(false),
                }
            }
            _ => assert!(false),
        };
    }

    fn init() -> OwnedDeps<MemoryStorage, MockApi, MockQuerier<AxelarQueryMsg>> {
        let addr = Addr::unchecked("axelar-gateway");
        let mut deps = OwnedDeps {
            storage: MockStorage::default(),
            api: MockApi::default(),
            querier: MockQuerier::<AxelarQueryMsg>::new(&[]),
            custom_query_type: PhantomData,
        };
        state::save_config(
            deps.as_mut().storage,
            &Config {
                axelarnet_gateway: addr.clone(),
            },
        )
        .unwrap();

        let mut querier = MockQuerier::<AxelarQueryMsg>::new(&[]);
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == &addr.to_string() => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::ChainName {} => {
                        Ok(to_json_binary(&ChainName::try_from(AXELAR_CHAIN_NAME).unwrap()).into())
                            .into()
                    }
                    _ => panic!("unsupported query"),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });
        querier = querier.with_custom_handler(|msg| match msg {
            AxelarQueryMsg::Evm(msg) => match msg {
                evm::query::QueryMsg::TokenInfo { chain, asset } => Ok(to_json_binary(
                    &(TokenInfoResponse {
                        asset: GATEWAY_TOKEN_ASSET_NAME.to_string(),
                        address: "".to_string(),
                        details: TokenDetails {
                            token_name: GATEWAY_TOKEN_ASSET_NAME.to_string(),
                            symbol: GATEWAY_TOKEN_DENOM.to_string(),
                            decimals: GATEWAY_TOKEN_DECIMALS as u32,
                            capacity: Uint256::one(),
                        },
                        confirmed: true,
                        is_external: true,
                        burner_code_hash: "".to_string(),
                    }),
                )
                .into())
                .into(),
                _ => panic!("unsupported query"),
            },
            _ => panic!("unsupported query"),
        });

        deps.querier = querier;
        deps
    }
}
