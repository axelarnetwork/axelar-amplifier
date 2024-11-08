use std::str::FromStr;
use std::hash::Hash;

use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::{nonempty, FnExt, VerificationStatus};
use cosmwasm_std::{Addr, CosmosMsg, Event, HexBinary, Response, Storage, Uint256};
use error_stack::{Result, ResultExt};
use itertools::Itertools;
use router_api::client::Router;
use router_api::{Address, ChainName, CrossChainId, Message};
use sha3::{Digest, Keccak256};
use xrpl_types::types::{XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLRemoteInterchainTokenInfo, XRPLToken, XRPLTokenOrXRP};
use xrpl_types::msg::{CrossChainMessage, XRPLMessage, XRPLUserMessageWithPayload};
use interchain_token_service::{self as its, TokenId};

use crate::contract::Error;
use crate::events::GatewayEvent;
use crate::msg::DeployInterchainTokenParams;
use crate::state;

pub fn verify_messages(
    verifier: &xrpl_voting_verifier::Client,
    msgs: Vec<XRPLMessage>,
    source_chain: &ChainName,
) -> Result<Response, Error> {
    let msgs_by_status = group_by_status(verifier, msgs, source_chain)?;
    let (msgs, events) = verify(verifier, msgs_by_status);
    Ok(Response::new().add_messages(msgs).add_events(events))
}

pub fn route_incoming_messages(
    store: &dyn Storage,
    verifier: &xrpl_voting_verifier::Client,
    router: &Router,
    msgs_with_payload: Vec<XRPLUserMessageWithPayload>,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_multisig: &XRPLAccountId,
    xrpl_chain_name: &ChainName,
) -> Result<Response, Error> {
    let msgs_by_status = group_by_status(verifier, msgs_with_payload, xrpl_chain_name)?;
    let (msgs, events) = route(store, router, msgs_by_status, its_hub, axelar_chain_name, xrpl_multisig, xrpl_chain_name)?;
    Ok(Response::new().add_messages(msgs).add_events(events))
}

pub fn group_by_status<T>(
    verifier: &xrpl_voting_verifier::Client,
    msgs: Vec<T>,
    source_chain: &ChainName,
) -> Result<Vec<(VerificationStatus, Vec<T>)>, Error>
where T: Into<XRPLMessage> + CrossChainMessage + Clone {
    let msgs = check_for_duplicates(msgs, source_chain)?;
    let msgs_status = fetch_msgs_status(verifier, msgs)?;
    let msgs_by_status = group_by_first(msgs_status);
    Ok(msgs_by_status)
}

pub fn fetch_msgs_status<T: Into<XRPLMessage> + Clone>(verifier: &xrpl_voting_verifier::Client, msgs: Vec<T>) -> Result<Vec<(VerificationStatus, T)>, Error> {
    Ok(verifier.messages_status(msgs.clone().into_iter().map(|m| m.into()).collect())
    .change_context(Error::MessageStatus)?
    .into_iter()
    .zip(msgs)
    .map(|(msg_status, msg)| (msg_status.status, msg))
    .collect::<Vec<_>>())
}

// because the messages came from the router, we can assume they are already verified
pub fn route_outgoing_messages(
    store: &mut dyn Storage,
    verified: Vec<Message>,
    its_hub: Addr,
    axelar_chain_name: &ChainName,
) -> Result<Response, Error> {
    let msgs = check_for_duplicates(verified, axelar_chain_name.into())?;

    for msg in msgs.iter() {
        if msg.source_address.to_string() != its_hub.to_string() {
            return Err(Error::OnlyItsHub(msg.cc_id.clone()).into());
        }

        if msg.cc_id.source_chain != axelar_chain_name.clone() {
            return Err(Error::OnlyAxelar(msg.cc_id.clone()).into())
        }

        state::save_outgoing_message(store, &msg.cc_id, msg)
            .change_context(Error::SaveOutgoingMessage)?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| GatewayEvent::RoutingOutgoing { msg }.into()),
    ))
}

const XRPL_LOCAL_TOKEN_DECIMALS: u8 = 15;

pub fn register_local_interchain_token(
    storage: &mut dyn Storage,
    xrpl_token: XRPLToken,
) -> Result<Response, Error> {
    let token_id = XRPLTokenOrXRP::Token(xrpl_token.clone()).token_id();
    state::save_token_info(storage, token_id.into(), &XRPLRemoteInterchainTokenInfo {
        xrpl_token: xrpl_token,
        canonical_decimals: XRPL_LOCAL_TOKEN_DECIMALS,
    }).unwrap();
    Ok(Response::new())
}

pub fn register_remote_interchain_token(
    storage: &mut dyn Storage,
    xrpl_multisig: XRPLAccountId,
    token_id: TokenId,
    xrpl_currency: XRPLCurrency,
    canonical_decimals: u8,
) -> Result<Response, Error> {
    let xrpl_token = XRPLToken {
        currency: xrpl_currency.clone(),
        issuer: xrpl_multisig,
    };
    state::save_xrpl_currency_token_id(storage, xrpl_currency, &token_id).unwrap();
    state::save_token_info(storage, token_id.into(), &XRPLRemoteInterchainTokenInfo {
        xrpl_token,
        canonical_decimals,
    }).unwrap();
    Ok(Response::new())
}

pub fn deploy_xrp_to_sidechain(
    storage: &mut dyn Storage,
    block_height: u64,
    router: &Router,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_chain_name: &ChainName,
    sidechain_name: &ChainName,
    xrpl_multisig: XRPLAccountId,
    deployment_params: nonempty::HexBinary,
) -> Result<Response, Error> {
    let token_id = XRPLTokenOrXRP::XRP.token_id();
    let its_msg = its::HubMessage::SendToHub {
        destination_chain: sidechain_name.clone().into(),
        message: its::Message::DeployTokenManager {
            token_id,
            token_manager_type: its::TokenManagerType::LockUnlock,
            params: deployment_params,
        },
    };

    let payload = its_msg.abi_encode();

    let msg = Message {
        cc_id: generate_cross_chain_id(storage, block_height, xrpl_chain_name.clone())?,
        source_address: Address::from_str(&xrpl_multisig.to_string()).unwrap(),
        destination_address: Address::from_str(its_hub.as_str()).unwrap(),
        destination_chain: axelar_chain_name.clone(),
        payload_hash: Keccak256::digest(payload.as_slice()).into(),
    };

    Ok(Response::new().add_messages(router.route(vec![msg.clone()])).add_event(GatewayEvent::RoutingIncoming { msg }.into()))
}

pub fn deploy_interchain_token(
    storage: &mut dyn Storage,
    block_height: u64,
    router: &Router,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_multisig: XRPLAccountId,
    xrpl_chain_name: &ChainName,
    xrpl_token: XRPLTokenOrXRP,
    destination_chain: ChainName,
    token_params: DeployInterchainTokenParams,
) -> Result<Response, Error> {
    // TODO: register deployment and don't allow duplicate deployments
    let token_id = xrpl_token.token_id();
    let its_msg = its::HubMessage::SendToHub {
        destination_chain: destination_chain.into(),
        message: its::Message::DeployInterchainToken {
            token_id,
            name: token_params.name,
            symbol: token_params.symbol,
            decimals: token_params.decimals,
            minter: token_params.minter,
        }
    };

    let payload = its_msg.abi_encode();

    let msg = Message {
        cc_id: generate_cross_chain_id(storage, block_height, xrpl_chain_name.clone())?,
        source_address: Address::from_str(&xrpl_multisig.to_string()).unwrap(),
        destination_address: Address::from_str(its_hub.as_str()).unwrap(),
        destination_chain: axelar_chain_name.clone(),
        payload_hash: Keccak256::digest(payload.as_slice()).into(),
    };

    Ok(Response::new().add_messages(router.route(vec![msg.clone()])).add_event(GatewayEvent::RoutingIncoming { msg }.into()))
}

// TODO: potentially query nexus, similarly to how axelarnet-gateway does
fn generate_cross_chain_id(
    storage: &mut dyn Storage,
    block_height: u64,
    chain_name: ChainName,
) -> Result<CrossChainId, Error> {
    // TODO: Retrieve the actual tx hash from core, since cosmwasm doesn't provide it.
    // Use the block height as the placeholder in the meantime.
    let message_id = HexTxHashAndEventIndex {
        tx_hash: Uint256::from(block_height).to_be_bytes(),
        event_index: state::increment_event_index(storage)
            .change_context(Error::EventIndex)?,
    };

    CrossChainId::new(chain_name, message_id).change_context(Error::InvalidCrossChainId)
}

fn check_for_duplicates<T: CrossChainMessage>(msgs: Vec<T>, source_chain: &ChainName) -> Result<Vec<T>, Error> {
    let duplicates: Vec<_> = msgs
        .iter()
        // the following two map instructions are separated on purpose
        // so the duplicate check is done on the typed id instead of just a string
        .map(|m| m.cc_id(source_chain.clone().into()))
        .duplicates()
        .map(|cc_id| cc_id.to_string())
        .collect();
    if !duplicates.is_empty() {
        return Err(Error::DuplicateMessageIds).attach_printable(duplicates.iter().join(", "));
    }
    Ok(msgs)
}

fn group_by_first<K, V>(msgs_with_status: impl IntoIterator<Item = (K, V)>) -> Vec<(K, Vec<V>)>
where K: Hash + Eq + Ord + Copy {
    msgs_with_status
        .into_iter()
        .map(|(status, msg)| (status, msg))
        .into_group_map()
        .into_iter()
        // sort by verification status so the order of messages is deterministic
        .sorted_by_key(|(status, _)| *status)
        .collect()
}

fn verify(
    verifier: &xrpl_voting_verifier::Client,
    msgs_by_status: Vec<(VerificationStatus, Vec<XRPLMessage>)>,
) -> (Option<CosmosMsg>, Vec<Event>) {
    msgs_by_status
        .into_iter()
        .map(|(status, msgs)| {
            (
                filter_verifiable_messages(status, &msgs),
                into_verify_events(status, msgs),
            )
        })
        .then(flat_unzip)
        .then(|(msgs, events)| (verifier.verify_messages(msgs), events))
}

fn route(
    store: &dyn Storage,
    router: &Router,
    msgs_by_status: Vec<(VerificationStatus, Vec<XRPLUserMessageWithPayload>)>,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_multisig: &XRPLAccountId,
    xrpl_chain_name: &ChainName,
) -> Result<(Option<CosmosMsg>, Vec<Event>), Error> {
    let mut route_msgs = Vec::new();
    let mut events = Vec::new();
    for (status, msgs) in &msgs_by_status {
        let mut its_msgs = Vec::new();
        for msg in msgs {
            its_msgs.push(to_its_message(store, msg, its_hub, axelar_chain_name, xrpl_multisig, xrpl_chain_name)?);
        }
        route_msgs.extend(filter_routable_messages(*status, &its_msgs));
        events.extend(into_route_events(*status, its_msgs));
    }
    Ok((router.route(route_msgs), events))
}

// not all messages are verifiable, so it's better to only take a reference and allocate a vector on demand
// instead of requiring the caller to allocate a vector for every message
fn filter_verifiable_messages(status: VerificationStatus, msgs: &[XRPLMessage]) -> Vec<XRPLMessage> {
    match status {
        VerificationStatus::Unknown
        | VerificationStatus::NotFoundOnSourceChain
        | VerificationStatus::FailedToVerify => msgs.to_vec(),
        _ => vec![],
    }
}

fn into_verify_events(status: VerificationStatus, msgs: Vec<XRPLMessage>) -> Vec<Event> {
    match status {
        VerificationStatus::Unknown
        | VerificationStatus::NotFoundOnSourceChain
        | VerificationStatus::FailedToVerify
        | VerificationStatus::InProgress => {
            messages_into_events(msgs, |msg| GatewayEvent::Verifying { msg })
        }
        VerificationStatus::SucceededOnSourceChain => {
            messages_into_events(msgs, |msg| GatewayEvent::AlreadyVerified { msg })
        }
        VerificationStatus::FailedOnSourceChain => {
            messages_into_events(msgs, |msg| GatewayEvent::AlreadyRejected { msg })
        }
    }
}

// not all messages are routable, so it's better to only take a reference and allocate a vector on demand
// instead of requiring the caller to allocate a vector for every message
fn filter_routable_messages(status: VerificationStatus, msgs: &[Message]) -> Vec<Message> {
    if status == VerificationStatus::SucceededOnSourceChain {
        msgs.to_vec()
    } else {
        vec![]
    }
}

fn into_route_events(status: VerificationStatus, msgs: Vec<Message>) -> Vec<Event> {
    match status {
        VerificationStatus::SucceededOnSourceChain => {
            messages_into_events(msgs, |msg| GatewayEvent::RoutingIncoming { msg })
        }
        _ => messages_into_events(msgs, |msg| GatewayEvent::UnfitForRouting { msg }),
    }
}

fn flat_unzip<A, B>(x: impl Iterator<Item = (Vec<A>, Vec<B>)>) -> (Vec<A>, Vec<B>) {
    let (x, y): (Vec<_>, Vec<_>) = x.unzip();
    (
        x.into_iter().flatten().collect(),
        y.into_iter().flatten().collect(),
    )
}

fn messages_into_events<T>(msgs: Vec<T>, transform: fn(T) -> GatewayEvent) -> Vec<Event> {
    msgs.into_iter().map(|msg| transform(msg).into()).collect()
}

fn scale_up_drops(drops: u64, to_decimals: u8) -> Uint256 {
    assert!(to_decimals > 6u8);
    let drops_uint256 = Uint256::from(drops);
    let scaling_factor = Uint256::from(10u128.pow(u32::from(to_decimals - 6u8)));
    drops_uint256 * scaling_factor
}

fn to_its_message(
    store: &dyn Storage,
    msg_with_payload: &XRPLUserMessageWithPayload,
    its_hub: &Addr,
    axelar_chain_name: &ChainName,
    xrpl_multisig: &XRPLAccountId,
    xrpl_chain_name: &ChainName,
) -> Result<Message, Error> {
    let user_message = &msg_with_payload.message;
    let token_id: its::TokenId = match user_message.amount.clone() {
        XRPLPaymentAmount::Drops(_) => XRPLTokenOrXRP::XRP.token_id(),
        XRPLPaymentAmount::Token(token, _) => {
            if token.issuer == xrpl_multisig.clone() {
                state::load_token_id(store, token.currency).map_err(|_| Error::InvalidToken)?
            } else {
                XRPLTokenOrXRP::Token(token).token_id()
            }
        }
    };

    if msg_with_payload.payload.is_none() {
        if user_message.payload_hash != [0u8; 32] {
            return Err(Error::PayloadHashMismatch {
                expected: user_message.payload_hash,
                actual: [0u8; 32],
            }.into());
        }
    } else {
        let payload_hash = Keccak256::digest(msg_with_payload.payload.clone().unwrap().as_slice()).into();
        if user_message.payload_hash != payload_hash {
            return Err(Error::PayloadHashMismatch {
                expected: user_message.payload_hash,
                actual: payload_hash,
            }.into());
        }
    }

    let interchain_transfer = its::Message::InterchainTransfer {
        token_id,
        source_address: nonempty::HexBinary::try_from(HexBinary::from(user_message.source_address.as_ref())).map_err(|_| Error::InvalidAddress)?,
        destination_address: user_message.clone().destination_address,
        amount: nonempty::Uint256::try_from(match user_message.clone().amount {
            XRPLPaymentAmount::Drops(drops) => if user_message.destination_chain == ChainName::from_str("xrpl-evm-sidechain").unwrap() { // TODO: create XRPL_EVM_SIDECHAIN_NAME const
                scale_up_drops(drops, 18u8)
            } else {
                Uint256::from(drops)
            },
            XRPLPaymentAmount::Token(_, token_amount) => Uint256::from(u64::from_be_bytes(token_amount.to_bytes())),
        }).unwrap(),
        data: msg_with_payload.payload.clone(),
    };

    let its_msg = its::HubMessage::SendToHub {
        destination_chain: user_message.clone().destination_chain.into(),
        message: interchain_transfer,
    };

    let payload = its_msg.abi_encode();

    Ok(Message {
        cc_id: user_message.cc_id(xrpl_chain_name.clone().into()),
        source_address: Address::from_str(&xrpl_multisig.to_string()).unwrap(),
        destination_address: Address::from_str(its_hub.as_str()).unwrap(),
        destination_chain: axelar_chain_name.clone(),
        payload_hash: Keccak256::digest(payload.as_slice()).into(),
    })
}

#[test]
fn receive_deploy_token_manager_from_hub() {
    let token_id = XRPLTokenOrXRP::XRP.token_id();
    let original = its::HubMessage::ReceiveFromHub {
        source_chain: ChainName::from_str("xrpl").unwrap().into(),
        message: its::Message::DeployTokenManager {
            token_id,
            token_manager_type: its::TokenManagerType::LockUnlock,
            params: nonempty::HexBinary::try_from(HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000a7baa2fe1df377147aaf49858b399f8c2564e8a400000000000000000000000000000000000000000000000000000000000000140A90c0Af1B07f6AC34f3520348Dbfae73BDa358E000000000000000000000000").unwrap()).unwrap(),
        },
    };

    let encoded = original.clone().abi_encode();
    let decoded = its::HubMessage::abi_decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn send_deploy_token_manager_to_hub() {
    let token_id = XRPLTokenOrXRP::XRP.token_id();
    let original = its::HubMessage::SendToHub {
        destination_chain: ChainName::from_str("xrpl-evm-sidechain").unwrap().into(),
        message: its::Message::DeployTokenManager {
            token_id,
            token_manager_type: its::TokenManagerType::LockUnlock,
            params: nonempty::HexBinary::try_from(HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000d4949664cd82660aae99bedc034a0dea8a0bd51700000000000000000000000000000000000000000000000000000000000000140A90c0Af1B07f6AC34f3520348Dbfae73BDa358E000000000000000000000000").unwrap()).unwrap(),
        },
    };

    let encoded = original.clone().abi_encode();
    let decoded = its::HubMessage::abi_decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn send_interchain_token_transfer_to_hub() {
    let interchain_transfer = its::Message::InterchainTransfer {
        token_id: XRPLTokenOrXRP::XRP.token_id(),
        source_address: nonempty::HexBinary::try_from(HexBinary::from(xrpl_types::types::XRPLAccountId::from_str("rNM8ue6DZpneFC4gBEJMSEdbwNEBZjs3Dy").unwrap().as_ref())).unwrap(),
        //destination_address: HexBinary::from_hex("dBfA2ae8aF2FA445B71F1C504d4BDCf8c1Fd5bE9").unwrap(),
        destination_address: nonempty::HexBinary::try_from(HexBinary::from_hex("d84f0525dC35448150Df0B83D5d0d574fa59785E").unwrap()).unwrap(),
        //amount: XRPLPaymentAmount::Drops(1420000).into(),
        amount: nonempty::Uint256::try_from(1000000u64).unwrap(),
        // data: None,
        data: Some(nonempty::HexBinary::try_from(HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001a4772656574696e67732066726f6d20746865205852504c203a29000000000000").unwrap()).unwrap()),
    };

    let its_msg = its::HubMessage::SendToHub {
        destination_chain: ChainName::from_str("xrpl-evm-sidechain").unwrap().into(),
        message: interchain_transfer,
    };

    let payload = its_msg.abi_encode();
    assert_eq!(payload, HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000127872706c2d65766d2d73696465636861696e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000008f08f438eb2beb8bda17828f245f463b7e67f99c0e1535adb1558aec9092b9ae00000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000f424000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000014928846baf59bd48c28b131855472d04c93bbd0b70000000000000000000000000000000000000000000000000000000000000000000000000000000000000014d84f0525dc35448150df0b83d5d0d574fa59785e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001a4772656574696e67732066726f6d20746865205852504c203a29000000000000").unwrap());
}

#[test]
fn receive_interchain_token_transfer_from_hub() {
    let original = its::HubMessage::ReceiveFromHub {
        source_chain: ChainName::from_str("xrpl").unwrap().into(),
        message: its::Message::InterchainTransfer {
            token_id: XRPLTokenOrXRP::XRP.token_id(),
            source_address: nonempty::HexBinary::try_from(HexBinary::from(vec![146, 136, 70, 186, 245, 155, 212, 140, 40, 177, 49, 133, 84, 114, 208, 76, 147, 187, 208, 183])).unwrap(),
            //destination_address: HexBinary::from_hex("dBfA2ae8aF2FA445B71F1C504d4BDCf8c1Fd5bE9").unwrap(),
            destination_address: nonempty::HexBinary::try_from(HexBinary::from_hex("d84f0525dC35448150Df0B83D5d0d574fa59785E").unwrap()).unwrap(),
            // amount: nonempty::Uint256::try_from(1420000000000000000u64).unwrap(),
            amount: nonempty::Uint256::try_from(1000000000000000000u64).unwrap(),
            // data: HexBinary::from(vec![]),
            data: Some(nonempty::HexBinary::try_from(HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001a4772656574696e67732066726f6d20746865205852504c203a29000000000000").unwrap()).unwrap()),
        },
    };

    let encoded = original.clone().abi_encode();
    let decoded = its::HubMessage::abi_decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}
