use axelar_core_std::nexus;
use axelar_wasm_std::{nonempty, FnExt, IntoContractError};
use cosmwasm_std::{Coin, DepsMut, HexBinary, QuerierWrapper, Response, Storage, Uint128, Uint256};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};
use sha3::{Digest, Keccak256};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{self, load_config, load_its_contract};
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
    #[error("failed to execute message")]
    FailedExecuteMessage,
    #[error("failed to generate token id")]
    FailedTokenIdGeneration,
    #[error("transfer amount exceeds Uint128 max")]
    TransferAmountOverflow,
    #[error("attached coin {attached:?} does not match expected coin {expected:?}")]
    IncorrectAttachedCoin {
        attached: Option<Coin>,
        expected: Option<Coin>,
    },
    #[error("failed to query nexus")]
    NexusQueryError,
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
    coin: Option<Coin>,
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

            verify_coin(&deps, &coin, &message, &cc_id.source_chain)?;

            Ok(send_to_destination(
                deps.storage,
                deps.querier,
                destination_chain.clone(),
                destination_address,
                destination_payload,
                gateway_token_transfer(&deps, &destination_chain, &message)?,
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

fn verify_coin(
    deps: &DepsMut,
    coin: &Option<Coin>,
    message: &Message,
    source_chain: &ChainNameRaw,
) -> Result<(), Error> {
    let expected_coin = gateway_token_transfer(deps, source_chain, message)?;
    ensure!(
        &expected_coin == coin,
        Error::IncorrectAttachedCoin {
            attached: coin.clone(),
            expected: expected_coin
        }
    );
    Ok(())
}

fn gateway_token_transfer(
    deps: &DepsMut,
    chain: &ChainNameRaw,
    message: &Message,
) -> Result<Option<Coin>, Error> {
    let client: nexus::Client = client::CosmosClient::new(deps.querier).into();
    let is_core_chain = client
        .is_chain_registered(&normalize(chain))
        .change_context(Error::NexusQueryError)?;

    if !is_core_chain {
        return Ok(None);
    }

    let token_id = message.token_id();
    let gateway_denom = state::may_load_gateway_denom(deps.storage, token_id)
        .change_context(Error::StorageError)?;
    match (gateway_denom, message) {
        (Some(denom), Message::InterchainTransfer { amount, .. }) => Ok(Some(Coin {
            denom: denom.to_string(),
            amount: Uint128::try_from(Uint256::from(*amount)).change_context(Error::TransferAmountOverflow)?,
        })),
        _ => Ok(None),
    }
}

fn send_to_destination(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: ChainNameRaw,
    destination_address: Address,
    payload: HexBinary,
    coin: Option<Coin>,
) -> Result<Response, Error> {
    let config = load_config(storage);

    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(querier, &config.axelarnet_gateway).into();

    let call_contract_msg = match coin {
        Some(coin) => gateway.call_contract_with_token(
            normalize(&destination_chain),
            destination_address,
            payload,
            coin,
        ),
        None => gateway.call_contract(normalize(&destination_chain), destination_address, payload),
    };

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
    use axelar_core_std::nexus;
    use axelar_core_std::nexus::query::IsChainRegisteredResponse;
    use axelar_core_std::query::AxelarQueryMsg;
    use axelar_wasm_std::assert_err_contains;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelarnet_gateway::msg::QueryMsg;
    use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, Coin, CosmosMsg, HexBinary, MemoryStorage, OwnedDeps,
        Uint128, Uint256, WasmMsg, WasmQuery,
    };
    use router_api::{ChainName, ChainNameRaw, CrossChainId};

    use super::{gateway_token_id, register_gateway_token, Error};
    use crate::contract::execute::{execute_message, register_its_contract};
    use crate::state::{self, Config};
    use crate::{HubMessage, Message};

    const CORE_CHAIN: &str = "ethereum";
    const AMPLIFIER_CHAIN: &str = "solana";
    const GATEWAY_TOKEN_DENOM: &str = "eth";
    const ITS_ADDRESS: &str = "68d30f47F19c07bCCEf4Ac7FAE2Dc12FCa3e0dC9";

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
    fn should_lock_and_unlock_gateway_token() {
        let mut deps = init();
        register_token_and_its_contracts(&mut deps);

        let destination_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let source_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let source_address =
            HexBinary::from_hex("4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();

        let token_id = gateway_token_id(&deps.as_mut(), GATEWAY_TOKEN_DENOM).unwrap();

        let coin = Coin {
            denom: GATEWAY_TOKEN_DENOM.to_string(),
            amount: Uint128::from(1500u128),
        };

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: token_id.clone(),
                source_address: source_address.clone().try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: coin.amount.try_into().unwrap(),
                data: None,
            },
        };
        assert_ok!(execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            Some(coin.clone()),
        ));

        let msg = HubMessage::SendToHub {
            destination_chain: source_chain.clone(),
            message: Message::InterchainTransfer {
                token_id,
                source_address: source_address.try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: coin.amount.try_into().unwrap(),
                data: None,
            },
        };

        let res = assert_ok!(execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: destination_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            None,
        ));

        match &res.messages[0].msg {
            CosmosMsg::Wasm(WasmMsg::Execute { funds, .. }) => {
                assert_eq!(funds.len(), 1);
                assert_eq!(funds.first().unwrap(), &coin);
            }
            _ => panic!("incorrect msg type"),
        };
    }

    #[test]
    fn should_reject_transfer_if_token_id_does_not_match() {
        let mut deps = init();
        register_token_and_its_contracts(&mut deps);

        let destination_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let source_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let source_address =
            HexBinary::from_hex("4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();

        let coin = Coin {
            denom: GATEWAY_TOKEN_DENOM.to_string(),
            amount: Uint128::from(1500u128),
        };

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: [0u8; 32].into(),
                source_address: source_address.try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: coin.amount.try_into().unwrap(),
                data: None,
            },
        };
        let res = execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            Some(coin.clone()),
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            Error::IncorrectAttachedCoin {
                attached: Some(coin),
                expected: None
            }
            .to_string()
        );
    }

    #[test]
    fn should_reject_transfer_if_amount_does_not_match_attached_token() {
        let mut deps = init();
        register_token_and_its_contracts(&mut deps);

        let destination_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let source_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let source_address =
            HexBinary::from_hex("4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();

        let token_id = gateway_token_id(&deps.as_mut(), GATEWAY_TOKEN_DENOM).unwrap();

        let coin = Coin {
            denom: GATEWAY_TOKEN_DENOM.to_string(),
            amount: Uint128::from(1500u128),
        };

        let amount_in_msg = coin.amount.strict_sub(Uint128::one());

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: token_id.clone(),
                source_address: source_address.try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: amount_in_msg.try_into().unwrap(),
                data: None,
            },
        };
        let res = execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            Some(coin.clone()),
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            Error::IncorrectAttachedCoin {
                attached: Some(coin.clone()),
                expected: Some(Coin {
                    denom: coin.denom,
                    amount: amount_in_msg
                })
            }
            .to_string()
        );
    }

    #[test]
    fn should_reject_transfer_with_token_if_source_chain_is_not_core() {
        let mut deps = init();
        register_token_and_its_contracts(&mut deps);

        let destination_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let source_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let source_address =
            HexBinary::from_hex("4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();

        let token_id = gateway_token_id(&deps.as_mut(), GATEWAY_TOKEN_DENOM).unwrap();

        let coin = Coin {
            denom: GATEWAY_TOKEN_DENOM.to_string(),
            amount: Uint128::from(1500u128),
        };

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: token_id.clone(),
                source_address: source_address.try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: coin.amount.try_into().unwrap(),
                data: None,
            },
        };
        let res = execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            Some(coin.clone()),
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            Error::IncorrectAttachedCoin {
                attached: Some(coin),
                expected: None
            }
            .to_string()
        );
    }

    #[test]
    fn should_reject_transfer_if_attached_token_is_not_registered() {
        let mut deps = init();
        register_token_and_its_contracts(&mut deps);

        let destination_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let source_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let source_address =
            HexBinary::from_hex("4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();

        let denom = "foobar";
        let token_id = gateway_token_id(&deps.as_mut(), denom).unwrap();

        let coin = Coin {
            denom: denom.to_string(),
            amount: Uint128::from(1500u128),
        };

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: token_id.clone(),
                source_address: source_address.try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: coin.amount.try_into().unwrap(),
                data: None,
            },
        };
        let res = execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            Some(coin.clone()),
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            Error::IncorrectAttachedCoin {
                attached: Some(coin),
                expected: None
            }
            .to_string()
        );
    }

    #[test]
    fn should_not_attach_coin_if_destination_is_not_core() {
        let mut deps = init();
        register_token_and_its_contracts(&mut deps);

        let destination_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let source_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let source_address =
            HexBinary::from_hex("4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();

        let token_id = gateway_token_id(&deps.as_mut(), GATEWAY_TOKEN_DENOM).unwrap();

        let coin = Coin {
            denom: GATEWAY_TOKEN_DENOM.to_string(),
            amount: Uint128::from(1500u128),
        };

        // send the token from core to an amplifier chain, should be escrowed
        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: token_id.clone(),
                source_address: source_address.clone().try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: coin.amount.try_into().unwrap(),
                data: None,
            },
        };
        let res = assert_ok!(execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            Some(coin.clone()),
        ));

        // no tokens attached, token is encoded purely as GMP
        assert_eq!(res.messages.len(), 1);
        match &res.messages[0].msg {
            CosmosMsg::Wasm(WasmMsg::Execute { funds, .. }) => assert_eq!(funds.len(), 0),
            _ => panic!("incorrect msg type"),
        };

        // now send from amplifier chain to another amplifier chain
        let second_destination_chain = ChainNameRaw::try_from("xrpl").unwrap();
        assert_ok!(register_its_contract(
            deps.as_mut(),
            second_destination_chain.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
        ));

        let msg = HubMessage::SendToHub {
            destination_chain: second_destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id,
                source_address: source_address.try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: coin.amount.try_into().unwrap(),
                data: None,
            },
        };

        let res = assert_ok!(execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: destination_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            None,
        ));

        // no tokens should be attached
        assert_eq!(res.messages.len(), 1);
        match &res.messages[0].msg {
            CosmosMsg::Wasm(WasmMsg::Execute { funds, .. }) => assert_eq!(funds.len(), 0),
            _ => panic!("incorrect msg type"),
        };
    }

    #[test]
    fn can_send_pure_gmp_from_core() {
        let mut deps = init();
        register_token_and_its_contracts(&mut deps);

        let destination_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let source_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let source_address =
            HexBinary::from_hex("4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();

        let denom = "wBTC";

        let token_id = gateway_token_id(&deps.as_mut(), denom).unwrap();

        // send the token from core to an amplifier chain, should be escrowed
        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: token_id.clone(),
                source_address: source_address.clone().try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: Uint256::one().try_into().unwrap(),
                data: None,
            },
        };

        assert_ok!(execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            None,
        ));
    }

    #[test]
    fn should_reject_transfer_from_core_if_gateway_token_is_not_attached() {
        let mut deps = init();
        register_token_and_its_contracts(&mut deps);

        let destination_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let source_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();
        let source_address =
            HexBinary::from_hex("4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97").unwrap();

        let token_id = gateway_token_id(&deps.as_mut(), GATEWAY_TOKEN_DENOM).unwrap();

        let coin = Coin {
            denom: GATEWAY_TOKEN_DENOM.to_string(),
            amount: Uint128::from(1500u128),
        };

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::InterchainTransfer {
                token_id: token_id.clone(),
                source_address: source_address.clone().try_into().unwrap(),
                destination_address: HexBinary::from_hex(ITS_ADDRESS)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                amount: coin.amount.try_into().unwrap(),
                data: None,
            },
        };
        let res = execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            None,
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            Error::IncorrectAttachedCoin {
                attached: None,
                expected: Some(coin)
            }
            .to_string()
        );
    }

    #[test]
    fn should_reject_message_if_coin_attached_but_not_interchain_transfer() {
        let mut deps = init();
        register_token_and_its_contracts(&mut deps);

        let destination_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let source_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();

        let token_id = gateway_token_id(&deps.as_mut(), GATEWAY_TOKEN_DENOM).unwrap();

        let coin = Coin {
            denom: GATEWAY_TOKEN_DENOM.to_string(),
            amount: Uint128::from(1500u128),
        };

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::DeployInterchainToken {
                token_id: token_id.clone(),
                name: "foobar".try_into().unwrap(),
                symbol: "FOO".try_into().unwrap(),
                decimals: 10u8,
                minter: Some(HexBinary::from([0u8; 32]).try_into().unwrap()),
            },
        };
        let res = execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
            Some(coin.clone()),
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            Error::IncorrectAttachedCoin {
                expected: None,
                attached: Some(coin)
            }
            .to_string()
        );
    }

    fn register_token_and_its_contracts(
        deps: &mut OwnedDeps<MemoryStorage, MockApi, MockQuerier<AxelarQueryMsg>>,
    ) {
        let amplifier_chain = ChainNameRaw::try_from(AMPLIFIER_CHAIN).unwrap();
        let core_chain = ChainNameRaw::try_from(CORE_CHAIN).unwrap();

        assert_ok!(register_gateway_token(
            deps.as_mut(),
            GATEWAY_TOKEN_DENOM.try_into().unwrap(),
            core_chain.clone()
        ));

        assert_ok!(register_its_contract(
            deps.as_mut(),
            core_chain.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
        ));

        assert_ok!(register_its_contract(
            deps.as_mut(),
            amplifier_chain.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
        ));
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
}
