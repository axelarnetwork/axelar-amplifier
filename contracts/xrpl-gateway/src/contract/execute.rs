use std::str::FromStr;
use std::hash::Hash;

use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::{nonempty, FnExt, VerificationStatus};
use cosmwasm_std::{Addr, CosmosMsg, Event, HexBinary, Response, Storage, Uint256};
use error_stack::{bail, ensure, report, Result, ResultExt};
use itertools::Itertools;
use router_api::client::Router;
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId, Message};
use sha3::{Digest, Keccak256};
use interchain_token_service::{self, TokenId};
use xrpl_types::types::{scale_to_decimals, XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLToken, XRPLTokenOrXrp, XRPL_ISSUED_TOKEN_DECIMALS, XRP_DECIMALS};
use xrpl_types::msg::{CrossChainMessage, XRPLMessage, XRPLUserMessageWithPayload};

use crate::contract::Error;
use crate::events::XRPLGatewayEvent;
use crate::msg::{InterchainTransfer, LinkToken, MessageWithPayload, TokenMetadata};
use crate::state::{self, Config};

pub fn verify_messages(
    verifier: &xrpl_voting_verifier::Client,
    msgs: Vec<XRPLMessage>,
    source_chain: &ChainName,
) -> Result<Response, Error> {
    let msgs_by_status = group_by_status(verifier, msgs, source_chain)?;
    let (msgs, events) = verify(verifier, msgs_by_status);
    Ok(Response::new().add_messages(msgs).add_events(events))
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

pub fn route_incoming_messages(
    storage: &mut dyn Storage,
    config: &Config,
    verifier: &xrpl_voting_verifier::Client,
    msgs_with_payload: Vec<XRPLUserMessageWithPayload>,
) -> Result<Response, Error> {
    let msgs_by_status = group_by_status(verifier, msgs_with_payload, &config.chain_name)?;
    let mut route_msgs = Vec::new();
    let mut events = Vec::new();
    for (status, msgs) in &msgs_by_status {
        let mut its_msgs = Vec::new();
        for msg in msgs {
            let interchain_transfer = translate_to_interchain_transfer(storage, config, msg)?;

            state::count_dust(storage, &msg.message.tx_id, &interchain_transfer.token_id, interchain_transfer.dust)
                .change_context(Error::State)?;

            match interchain_transfer.message_with_payload {
                Some(message_with_payload) => {
                    its_msgs.push(message_with_payload.message.clone());
                    events.extend(vec![
                        into_route_event(status, message_with_payload.message.clone()),
                        Event::from(XRPLGatewayEvent::ContractCalled {
                            msg: message_with_payload.message,
                            payload: message_with_payload.payload,
                        }),
                    ]);
                }
                None => ()
            }
        }
        route_msgs.extend(filter_routable_messages(*status, &its_msgs));
    }

    let router = Router::new(config.router.clone());
    Ok(Response::new().add_messages(router.route(route_msgs)).add_events(events))
}

const PREFIX_TOKEN_ID: &[u8] = b"its-interchain-token-id";
const PREFIX_CUSTOM_TOKEN_SALT: &[u8] = b"custom-token-salt";
const TOKEN_FACTORY_DEPLOYER: &str = "";

fn token_id(salt: [u8; 32]) -> TokenId {
    let token_id: [u8; 32] = Keccak256::digest(&[
        Keccak256::digest(PREFIX_TOKEN_ID).as_slice(),
        Addr::unchecked(TOKEN_FACTORY_DEPLOYER).as_bytes(),
        &salt,
    ].concat()).into();
    TokenId::new(token_id)
}

fn linked_token_deploy_salt(chain_name_hash: [u8; 32], deployer: Addr, salt: [u8; 32]) -> [u8; 32] {
    Keccak256::digest(&[
        Keccak256::digest(PREFIX_CUSTOM_TOKEN_SALT).as_slice(),
        &chain_name_hash,
        deployer.as_bytes(),
        &salt,
    ].concat()).into()
}

pub fn linked_token_id(chain_name_hash: [u8; 32], deployer: Addr, salt: [u8; 32]) -> TokenId {
    token_id(linked_token_deploy_salt(chain_name_hash, deployer, salt))
}

pub fn chain_name_hash(chain_name: ChainName) -> [u8; 32] {
    Keccak256::digest(chain_name.to_string()).into()
}

fn load_token_id(storage: &dyn Storage, xrpl_multisig: XRPLAccountId, token: &XRPLToken) -> Result<TokenId, Error> {
    let token_id = if token.is_remote(xrpl_multisig.clone()) {
        state::load_remote_token_id(storage, &token.currency)
            .change_context(Error::InvalidToken)?
    } else {
        state::load_local_token_id(storage, &token)
            .change_context(Error::InvalidToken)?
    };

    Ok(token_id)
}

pub fn translate_to_interchain_transfer(
    storage: &dyn Storage,
    config: &Config,
    xrpl_user_message_with_payload: &XRPLUserMessageWithPayload,
) -> Result<InterchainTransfer, Error> {
    let user_message = &xrpl_user_message_with_payload.message;

    match &xrpl_user_message_with_payload.payload {
        None => {
            ensure!(
                user_message.payload_hash.is_none(),
                Error::PayloadHashGivenWithoutPayload(user_message.payload_hash.unwrap().into())
            );
        }
        Some(payload) => {
            match user_message.payload_hash {
                None => {
                    return Err(report!(Error::PayloadHashEmpty));
                }
                Some(hash) => {
                    let payload_hash = <[u8; 32]>::from(Keccak256::digest(payload.as_ref()));
                    ensure!(
                        hash == payload_hash,
                        Error::PayloadHashMismatch {
                            expected: payload_hash.into(),
                            actual: hash.into(),
                        }
                    )
                }
            }
        }
    }

    let token_id = match &user_message.amount {
        XRPLPaymentAmount::Drops(_) => state::load_xrp_token_id(storage).change_context(Error::InvalidToken)?,
        XRPLPaymentAmount::Issued(token, _) => load_token_id(storage, config.xrpl_multisig.clone(), token)?,
    };

    let source_address = nonempty::HexBinary::try_from(HexBinary::from(user_message.source_address.as_ref()))
        .change_context(Error::InvalidAddress)?;
    let destination_address = user_message.destination_address.clone();
    let destination_chain = ChainNameRaw::from(user_message.destination_chain.clone());

    let (amount, dust) = match user_message.amount.clone() {
        XRPLPaymentAmount::Drops(drops) => {
            (Uint256::from(drops), XRPLPaymentAmount::Drops(0u64))
        }
        XRPLPaymentAmount::Issued(token, token_amount) => {
            let destination_decimals = state::load_token_instance_decimals(storage, destination_chain.clone(), token_id.clone())
                .change_context(Error::TokenNotRegisteredForChain {
                    token_id: token_id.to_owned(),
                    chain_name: destination_chain.to_owned(),
                })?;

            let (amount, dust) = scale_to_decimals(token_amount, destination_decimals)
                .change_context(Error::InvalidTransferAmount {
                    destination_chain,
                    amount: user_message.amount.to_owned(),
                })?;

            (amount, XRPLPaymentAmount::Issued(token, dust))
        }
    };

    if amount.is_zero() {
        return Ok(InterchainTransfer {
            message_with_payload: None,
            token_id,
            dust,
        });
    }

    let payload = interchain_token_service::HubMessage::SendToHub {
        destination_chain: user_message.clone().destination_chain.into(),
        message: interchain_token_service::Message::InterchainTransfer(
            interchain_token_service::InterchainTransfer {
                token_id: token_id.clone(),
                source_address,
                destination_address,
                amount: amount.try_into().expect("amount cannot be zero"),
                data: xrpl_user_message_with_payload.payload.clone(),
            },
        ),
    }.abi_encode();
    let cc_id = user_message.cc_id(config.chain_name.clone().into());
    let its_msg = construct_its_hub_message(config, cc_id, payload.clone())?;

    Ok(InterchainTransfer {
        message_with_payload: Some(MessageWithPayload {
            message: its_msg,
            payload,
        }),
        token_id,
        dust,
    })
}

// because the messages came from the router, we can assume they are already verified
pub fn route_outgoing_messages(
    storage: &mut dyn Storage,
    verified: Vec<Message>,
    its_hub: Addr,
    its_hub_chain_name: &ChainName,
) -> Result<Response, Error> {
    let msgs = check_for_duplicates(verified, its_hub_chain_name.into())?;

    for msg in msgs.iter() {
        if msg.source_address.to_string() != its_hub.to_string() {
            return Err(Error::OnlyFromItsHub(msg.cc_id.clone()).into());
        }

        if msg.cc_id.source_chain != its_hub_chain_name.clone() {
            return Err(Error::OnlyFromItsHubChain(msg.cc_id.clone()).into())
        }

        state::save_outgoing_message(storage, &msg.cc_id, msg)
            .change_context(Error::SaveOutgoingMessage)?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter().map(|msg| XRPLGatewayEvent::RoutingOutgoing { msg }),
    ))
}

pub fn register_token_metadata(
    config: &Config,
    block_height: u64,
    xrpl_token: XRPLTokenOrXrp,
) -> Result<Response, Error> {
    let hub_msg = interchain_token_service::HubMessage::RegisterTokenMetadata(
        interchain_token_service::RegisterTokenMetadata {
            decimals: match xrpl_token {
                XRPLTokenOrXrp::Xrp => XRP_DECIMALS,
                XRPLTokenOrXrp::Issued(_) => XRPL_ISSUED_TOKEN_DECIMALS,
            },
            token_address: nonempty::HexBinary::try_from(xrpl_token.to_string().as_bytes().to_vec()).change_context(Error::InvalidToken)?,
        }
    );

    route_hub_message(config, block_height, hub_msg)
}

pub fn register_xrp(
    storage: &mut dyn Storage,
    config: &Config,
    sender: Addr,
    salt: [u8; 32],
) -> Result<Response, Error> {
    let chain_name_hash = chain_name_hash(config.chain_name.clone());
    let token_id = linked_token_id(chain_name_hash, sender, salt);
    state::save_xrp_token_id(storage, &token_id)
        .change_context(Error::State)?;

    Ok(Response::default())
}

pub fn register_local_token(
    storage: &mut dyn Storage,
    config: &Config,
    sender: Addr,
    salt: [u8; 32],
    xrpl_token: XRPLToken,
) -> Result<Response, Error> {
    ensure!(
        xrpl_token.is_local(config.xrpl_multisig.clone()),
        Error::TokenNotLocal(XRPLTokenOrXrp::Issued(xrpl_token))
    );

    let chain_name_hash = chain_name_hash(config.chain_name.clone());
    let token_id = linked_token_id(chain_name_hash, sender, salt);

    match state::may_load_local_token_id(storage, &xrpl_token)
        .change_context(Error::State)?
    {
        Some(deployed_token_id) => {
            ensure!(
                deployed_token_id == token_id,
                Error::LocalTokenDeployedIdMismatch {
                    xrpl_token,
                    expected: deployed_token_id,
                    actual: token_id,
                }
            );
        }
        None => {
            state::save_local_token_id(storage, &xrpl_token, &token_id)
                .change_context(Error::State)?;
        }
    }

    match state::may_load_xrpl_token(storage, &token_id)
        .change_context(Error::State)?
    {
        Some(deployed_xrpl_token) => {
            ensure!(
                deployed_xrpl_token == xrpl_token,
                Error::LocalTokenDeployedMismatch {
                    token_id,
                    expected: deployed_xrpl_token,
                    actual: xrpl_token,
                }
            );
        }
        None => {
            state::save_xrpl_token(storage, &token_id, &xrpl_token)
                .change_context(Error::State)?;
        }
    }

    Ok(Response::default())
}

pub fn register_remote_token(
    storage: &mut dyn Storage,
    xrpl_multisig: XRPLAccountId,
    token_id: TokenId,
    xrpl_currency: XRPLCurrency,
) -> Result<Response, Error> {
    match state::may_load_remote_token_id(storage, &xrpl_currency)
        .change_context(Error::State)?
    {
        Some(deployed_token_id) => {
            ensure!(
                deployed_token_id == token_id,
                Error::RemoteTokenDeployedIdMismatch {
                    xrpl_currency,
                    expected: deployed_token_id,
                    actual: token_id,
                }
            );
        }
        None => {
            state::save_remote_token_id(storage, &xrpl_currency, &token_id)
                .change_context(Error::State)?;
        }
    }

    match state::may_load_xrpl_token(storage, &token_id)
        .change_context(Error::State)?
    {
        Some(deployed_xrpl_token) => {
            ensure!(
                deployed_xrpl_token.currency == xrpl_currency,
                Error::RemoteTokenDeployedCurrencyMismatch {
                    token_id,
                    expected: deployed_xrpl_token.currency,
                    actual: xrpl_currency,
                }
            );
            ensure!(
                deployed_xrpl_token.is_remote(xrpl_multisig.clone()),
                Error::RemoteTokenDeployedIssuerMismatch {
                    token_id,
                    expected: deployed_xrpl_token.issuer,
                    actual: xrpl_multisig,
                }
            );
        }
        None => {
            let xrpl_token = XRPLToken {
                currency: xrpl_currency.clone(),
                issuer: xrpl_multisig.clone(),
            };

            state::save_xrpl_token(storage, &token_id, &xrpl_token)
                .change_context(Error::State)?;
        }
    }

    Ok(Response::default())
}

fn construct_its_hub_message(
    config: &Config,
    cc_id: CrossChainId,
    payload: HexBinary,
) -> Result<Message, Error> {
    Ok(Message {
        cc_id,
        source_address: Address::from_str(&config.xrpl_multisig.to_string())
            .change_context(Error::InvalidSourceAddress)?,
        destination_address: Address::from_str(config.its_hub.as_str())
            .change_context(Error::InvalidDestinationAddress)?,
        destination_chain: config.its_hub_chain_name.clone(),
        payload_hash: Keccak256::digest(payload.as_slice()).into(),
    })
}

pub fn register_token_instance(
    storage: &mut dyn Storage,
    config: &Config,
    token_id: TokenId,
    chain: ChainNameRaw,
    decimals: u8,
) -> Result<Response, Error> {
    if decimals > 50 { // TODO: Don't hardcode.
        bail!(Error::InvalidDecimals(decimals));
    }

    if chain == config.chain_name {
        bail!(Error::ForbiddenChain(chain));
    }

    match state::may_load_token_instance_decimals(storage, chain.clone(), token_id.clone())
        .change_context(Error::State)?
    {
        Some(expected_decimals) => {
            ensure!(
                decimals == expected_decimals,
                Error::TokenDeployedDecimalsMismatch {
                    token_id: token_id.clone(),
                    expected: expected_decimals,
                    actual: decimals,
                }
            );
        }
        None => {
            state::save_token_instance_decimals(storage, chain.clone(), token_id, decimals)
                .change_context(Error::State)?;
        }
    }

    Ok(Response::default())
}

fn route_hub_message(
    config: &Config,
    block_height: u64,
    hub_message: interchain_token_service::HubMessage,
) -> Result<Response, Error> {
    let payload = hub_message.abi_encode();
    let cc_id = unique_cross_chain_id(block_height, config.chain_name.clone())?;
    let its_msg = construct_its_hub_message(config, cc_id, payload.clone())?;

    let router = Router::new(config.router.clone());
    Ok(Response::new()
        .add_messages(router.route(vec![its_msg.clone()]))
        .add_events(vec![
            XRPLGatewayEvent::RoutingIncoming { msg: its_msg.clone() },
            XRPLGatewayEvent::ContractCalled { msg: its_msg, payload },
        ]))
}

pub fn link_token(
    storage: &mut dyn Storage,
    config: &Config,
    block_height: u64,
    sender: Addr,
    salt: [u8; 32],
    destination_chain: ChainNameRaw,
    link_token: LinkToken,
) -> Result<Response, Error> {
    ensure!(
        destination_chain != config.chain_name,
        Error::InvalidDestinationChain(destination_chain)
    );

    let chain_name_hash = chain_name_hash(config.chain_name.clone());
    let token_id = linked_token_id(chain_name_hash, sender, salt);

    let xrp_token_id = state::load_xrp_token_id(storage).change_context(Error::InvalidToken)?;
    let xrpl_token = if token_id == xrp_token_id {
        XRPLTokenOrXrp::Xrp
    } else {
        let token = state::load_xrpl_token(storage, &token_id).change_context(Error::InvalidToken)?;
        register_token_instance(storage, config, token_id.clone(), destination_chain.clone(), XRPL_ISSUED_TOKEN_DECIMALS)?;
        XRPLTokenOrXrp::Issued(token)
    };

    let its_msg = interchain_token_service::Message::LinkToken(
        interchain_token_service::LinkToken {
            token_id: token_id,
            token_manager_type: link_token.token_manager_type,
            source_token_address: nonempty::HexBinary::try_from(xrpl_token.to_string().as_bytes().to_vec()).change_context(Error::InvalidToken)?,
            destination_token_address: link_token.destination_token_address,
            params: link_token.params,
        }
    );

    let hub_msg = interchain_token_service::HubMessage::SendToHub { destination_chain, message: its_msg };
    route_hub_message(config, block_height, hub_msg)
}

pub fn deploy_remote_token(
    storage: &mut dyn Storage,
    config: &Config,
    block_height: u64,
    token: XRPLTokenOrXrp,
    destination_chain: ChainNameRaw,
    token_metadata: TokenMetadata,
) -> Result<Response, Error> {
    ensure!(
        destination_chain != config.chain_name,
        Error::InvalidDestinationChain(destination_chain)
    );

    let (token_id, destination_decimals) = match token {
        XRPLTokenOrXrp::Xrp => (
            state::load_xrp_token_id(storage).change_context(Error::InvalidToken)?,
            XRP_DECIMALS,
        ),
        XRPLTokenOrXrp::Issued(xrpl_token) => (
            // load_token_id(storage, config.xrpl_multisig.clone(), &xrpl_token)?,
            state::load_local_token_id(storage, &xrpl_token).change_context(Error::InvalidToken)?,
            XRPL_ISSUED_TOKEN_DECIMALS,
        )
    };

    register_token_instance(storage, config, token_id.clone(), destination_chain.clone(), destination_decimals)?;

    let its_msg = interchain_token_service::Message::DeployInterchainToken(
        interchain_token_service::DeployInterchainToken{
            token_id: token_id.clone(),
            name: token_metadata.name,
            symbol: token_metadata.symbol,
            decimals: destination_decimals,
            minter: token_metadata.minter,
        }
    );

    let hub_msg = interchain_token_service::HubMessage::SendToHub { destination_chain, message: its_msg };
    route_hub_message(config, block_height, hub_msg)
}

// TODO: Potentially query nexus, similarly to how axelarnet-gateway does.
fn unique_cross_chain_id(block_height: u64, chain_name: ChainName) -> Result<CrossChainId, Error> {
    // TODO: Retrieve the actual tx hash from core, since cosmwasm doesn't provide it.
    // Use the block height as the placeholder in the meantime.
    let message_id = HexTxHash::new(Uint256::from(block_height).to_be_bytes());

    CrossChainId::new(chain_name, message_id).change_context(Error::InvalidCrossChainId)
}

fn group_by_status<T>(
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

fn fetch_msgs_status<T: Into<XRPLMessage> + Clone>(verifier: &xrpl_voting_verifier::Client, msgs: Vec<T>) -> Result<Vec<(VerificationStatus, T)>, Error> {
    Ok(verifier.messages_status(msgs.clone().into_iter().map(|m| m.into()).collect())
    .change_context(Error::MessageStatus)?
    .into_iter()
    .zip(msgs)
    .map(|(msg_status, msg)| (msg_status.status, msg))
    .collect::<Vec<_>>())
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
            messages_into_events(msgs, |msg| XRPLGatewayEvent::Verifying { msg })
        }
        VerificationStatus::SucceededOnSourceChain => {
            messages_into_events(msgs, |msg| XRPLGatewayEvent::AlreadyVerified { msg })
        }
        VerificationStatus::FailedOnSourceChain => {
            messages_into_events(msgs, |msg| XRPLGatewayEvent::AlreadyRejected { msg })
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

fn into_route_event(status: &VerificationStatus, msg: Message) -> Event {
    match status {
        &VerificationStatus::SucceededOnSourceChain => {
            XRPLGatewayEvent::RoutingIncoming { msg }.into()
        }
        _ => XRPLGatewayEvent::UnfitForRouting { msg }.into(),
    }
}

fn flat_unzip<A, B>(x: impl Iterator<Item = (Vec<A>, Vec<B>)>) -> (Vec<A>, Vec<B>) {
    let (x, y): (Vec<_>, Vec<_>) = x.unzip();
    (
        x.into_iter().flatten().collect(),
        y.into_iter().flatten().collect(),
    )
}

fn messages_into_events<T>(msgs: Vec<T>, transform: fn(T) -> XRPLGatewayEvent) -> Vec<Event> {
    msgs.into_iter().map(|msg| transform(msg).into()).collect()
}
