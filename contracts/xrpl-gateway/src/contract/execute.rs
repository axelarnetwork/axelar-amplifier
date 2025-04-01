use std::hash::Hash;
use std::str::FromStr;

use axelar_core_std::nexus;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::{address, nonempty, permission_control, FnExt, VerificationStatus};
use cosmwasm_std::{Addr, CosmosMsg, DepsMut, Event, HexBinary, Response, Storage, Uint256};
use error_stack::{bail, ensure, report, Result, ResultExt};
use interchain_token_service::{self, TokenId};
use itertools::Itertools;
use router_api::client::Router;
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId, Message};
use sha3::{Digest, Keccak256};
use xrpl_types::msg::{
    WithPayload, XRPLAddGasMessage, XRPLCallContractMessage, XRPLInterchainTransferMessage,
    XRPLMessage,
};
use xrpl_types::types::{
    scale_to_decimals, XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLToken, XRPLTokenOrXrp,
    XRPL_ISSUED_TOKEN_DECIMALS,
};

use crate::contract::Error;
use crate::events::XRPLGatewayEvent;
use crate::msg::{CallContract, InterchainTransfer, LinkToken, MessageWithPayload, TokenMetadata};
use crate::state::{self, Config};
use crate::token_id;

const PREFIX_CROSS_CHAIN_ID: &[u8] = b"cross-chain-id";

pub fn verify_messages(
    verifier: &xrpl_voting_verifier::Client,
    msgs: Vec<XRPLMessage>,
) -> Result<Response, Error> {
    let msgs_by_status = group_by_status(verifier, msgs)?;
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
    msgs_with_payload: Vec<WithPayload<XRPLMessage>>,
) -> Result<Response, Error> {
    let msgs_by_status = group_by_status(verifier, msgs_with_payload)?;
    let mut route_msgs = Vec::new();
    let mut events = Vec::new();
    for (status, msgs) in &msgs_by_status {
        let mut msgs_to_route = Vec::new();
        for msg in msgs {
            let message_with_payload = match msg.message.clone() {
                XRPLMessage::InterchainTransferMessage(interchain_transfer_message) => {
                    let InterchainTransfer {
                        message_with_payload,
                        token_id,
                    } = translate_to_interchain_transfer(
                        storage,
                        config,
                        &interchain_transfer_message,
                        msg.payload.clone(),
                    )?;

                    if status == &VerificationStatus::SucceededOnSourceChain {
                        state::count_gas(
                            storage,
                            &interchain_transfer_message.tx_id,
                            &token_id,
                            interchain_transfer_message.gas_fee_amount.clone(),
                        )
                        .change_context(Error::State)?;
                    }

                    message_with_payload
                }
                XRPLMessage::CallContractMessage(call_contract_message) => {
                    let payload = if let Some(payload) = msg.payload.clone() {
                        payload
                    } else {
                        return Err(report!(Error::PayloadHashEmpty));
                    };

                    let CallContract {
                        message_with_payload,
                        gas_token_id,
                    } = translate_to_call_contract(
                        storage,
                        config,
                        &call_contract_message,
                        payload.clone(),
                    )?;

                    if status == &VerificationStatus::SucceededOnSourceChain {
                        state::count_gas(
                            storage,
                            &call_contract_message.tx_id,
                            &gas_token_id,
                            call_contract_message.gas_fee_amount.clone(),
                        )
                        .change_context(Error::State)?;
                    }

                    Some(message_with_payload)
                }
                _ => {
                    return Err(report!(Error::UnsupportedIncomingMessage(
                        msg.message.to_owned()
                    )))
                }
            };

            if let Some(MessageWithPayload {
                message: msg,
                payload,
            }) = message_with_payload
            {
                msgs_to_route.push(msg.clone());
                events.extend(vec![
                    into_route_event(status, msg.clone()),
                    Event::from(XRPLGatewayEvent::ContractCalled {
                        msg,
                        payload: payload.into(),
                    }),
                ]);
            }
        }
        route_msgs.extend(filter_routable_messages(*status, &msgs_to_route));
    }

    let router = Router::new(config.router.clone());
    Ok(Response::new()
        .add_messages(router.route(route_msgs))
        .add_events(events))
}

pub fn payment_amount_to_token_id(
    storage: &dyn Storage,
    config: &Config,
    amount: &XRPLPaymentAmount,
) -> Result<TokenId, Error> {
    match amount {
        XRPLPaymentAmount::Drops(_) => Ok(config.xrp_token_id),
        XRPLPaymentAmount::Issued(token, _) => {
            state::load_token_id(storage, config.xrpl_multisig.clone(), token)
                .change_context(Error::State)
        }
    }
}

pub fn confirm_add_gas_messages(
    storage: &mut dyn Storage,
    config: &Config,
    verifier: &xrpl_voting_verifier::Client,
    messages: Vec<XRPLAddGasMessage>,
) -> Result<Response, Error> {
    let msgs_by_status = group_by_status(verifier, messages)?;
    let successful_msgs = msgs_by_status
        .iter()
        .filter(|(status, _)| *status == VerificationStatus::SucceededOnSourceChain)
        .flat_map(|(_, msgs)| msgs)
        .collect::<Vec<_>>();

    for msg in successful_msgs {
        let token_id = payment_amount_to_token_id(storage, config, &msg.amount)?;
        state::count_gas(storage, &msg.tx_id, &token_id, msg.amount.clone())
            .change_context(Error::State)?;
    }

    Ok(Response::default())
}

pub fn update_admin(deps: DepsMut, new_admin_address: String) -> Result<Response, Error> {
    let new_admin = address::validate_cosmwasm_address(deps.api, &new_admin_address)
        .map_err(|_| Error::FailedToUpdateAdmin)?;
    permission_control::set_admin(deps.storage, &new_admin)
        .map_err(|_| Error::FailedToUpdateAdmin)?;
    Ok(Response::new())
}

pub fn translate_to_interchain_transfer(
    storage: &dyn Storage,
    config: &Config,
    interchain_transfer_message: &XRPLInterchainTransferMessage,
    payload: Option<nonempty::HexBinary>,
) -> Result<InterchainTransfer, Error> {
    match payload.clone() {
        None => {
            ensure!(
                interchain_transfer_message.payload_hash.is_none(),
                Error::PayloadHashGivenWithoutPayload(
                    interchain_transfer_message.payload_hash.unwrap().into()
                )
            );
        }
        Some(payload) => match interchain_transfer_message.payload_hash {
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
        },
    }

    let token_id = payment_amount_to_token_id(
        storage,
        config,
        &interchain_transfer_message.transfer_amount,
    )?;

    let source_address = nonempty::HexBinary::try_from(HexBinary::from(
        interchain_transfer_message
            .source_address
            .to_string()
            .as_bytes(),
    ))
    .change_context(Error::InvalidAddress)?;
    let destination_address = interchain_transfer_message.destination_address.clone();
    let destination_chain =
        ChainNameRaw::from(interchain_transfer_message.destination_chain.clone());

    let transfer_amount = &interchain_transfer_message.transfer_amount;

    let amount = match transfer_amount.clone() {
        XRPLPaymentAmount::Drops(drops) => Uint256::from(drops),
        XRPLPaymentAmount::Issued(_token, token_amount) => {
            let destination_decimals =
                state::load_token_instance_decimals(storage, destination_chain.clone(), token_id)
                    .change_context(Error::TokenNotRegisteredForChain {
                    token_id: token_id.to_owned(),
                    chain_name: destination_chain.to_owned(),
                })?;

            scale_to_decimals(token_amount, destination_decimals).change_context(
                Error::InvalidTransferAmount {
                    destination_chain,
                    amount: transfer_amount.to_owned(),
                },
            )?
        }
    };

    if amount.is_zero() {
        return Ok(InterchainTransfer {
            message_with_payload: None,
            token_id,
        });
    }

    let payload = interchain_token_service::HubMessage::SendToHub {
        destination_chain: interchain_transfer_message.clone().destination_chain.into(),
        message: interchain_token_service::Message::InterchainTransfer(
            interchain_token_service::InterchainTransfer {
                token_id,
                source_address,
                destination_address: nonempty::HexBinary::try_from(
                    HexBinary::from_hex(&destination_address)
                        .change_context(Error::InvalidAddress)?,
                )
                .change_context(Error::InvalidAddress)?,
                amount: amount.try_into().expect("amount cannot be zero"),
                data: payload.clone(),
            },
        ),
    }
    .abi_encode();

    let cc_id = interchain_transfer_message.cc_id(config.chain_name.clone().into());
    let its_msg = construct_its_hub_message(config, cc_id, payload.clone())?;

    Ok(InterchainTransfer {
        message_with_payload: Some(MessageWithPayload {
            message: its_msg,
            payload: TryInto::<nonempty::HexBinary>::try_into(payload)
                .change_context(Error::PayloadEncodingFailed)?,
        }),
        token_id,
    })
}

pub fn translate_to_call_contract(
    storage: &dyn Storage,
    config: &Config,
    call_contract_message: &XRPLCallContractMessage,
    payload: nonempty::HexBinary,
) -> Result<CallContract, Error> {
    let payload_hash = <[u8; 32]>::from(Keccak256::digest(payload.as_ref()));
    let expected_payload_hash = call_contract_message.payload_hash;
    ensure!(
        payload_hash == expected_payload_hash,
        Error::PayloadHashMismatch {
            expected: expected_payload_hash.into(),
            actual: payload_hash.into(),
        }
    );

    let gas_token_id =
        payment_amount_to_token_id(storage, config, &call_contract_message.gas_fee_amount)?;
    let destination_address = call_contract_message.destination_address.clone();
    let destination_chain = call_contract_message.destination_chain.clone();

    let cc_id = call_contract_message.cc_id(config.chain_name.clone().into());
    let message = Message {
        cc_id,
        source_address: Address::from_str(&call_contract_message.source_address.to_string())
            .change_context(Error::InvalidSourceAddress)?,
        destination_address: Address::from_str(&destination_address)
            .change_context(Error::InvalidDestinationAddress)?,
        destination_chain,
        payload_hash: call_contract_message.payload_hash,
    };

    Ok(CallContract {
        message_with_payload: MessageWithPayload { message, payload },
        gas_token_id,
    })
}

// because the messages came from the router, we can assume they are already verified
pub fn route_outgoing_messages(
    storage: &mut dyn Storage,
    verified: Vec<Message>,
    its_hub: Addr,
    its_hub_chain_name: &ChainName,
) -> Result<Response, Error> {
    let msgs = check_for_duplicates(verified, |m| m.cc_id.clone())?;

    for msg in msgs.iter() {
        if msg.source_address.to_string() != its_hub.to_string() {
            return Err(Error::OnlyFromItsHub(msg.cc_id.clone()).into());
        }

        if msg.cc_id.source_chain != its_hub_chain_name.clone() {
            return Err(Error::OnlyFromItsHubChain(msg.cc_id.clone()).into());
        }

        state::save_outgoing_message(storage, &msg.cc_id, msg)
            .change_context(Error::SaveOutgoingMessage)?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| XRPLGatewayEvent::RoutingOutgoing { msg }),
    ))
}

pub fn register_token_metadata(
    config: &Config,
    nexus_client: &nexus::Client,
    xrpl_token: XRPLTokenOrXrp,
) -> Result<Response, Error> {
    let hub_msg = interchain_token_service::HubMessage::RegisterTokenMetadata(
        interchain_token_service::RegisterTokenMetadata {
            decimals: xrpl_token.decimals(),
            token_address: xrpl_token.token_address(),
        },
    );

    route_hub_message(config, nexus_client, hub_msg)
}

pub fn register_local_token(
    storage: &mut dyn Storage,
    config: &Config,
    xrpl_token: XRPLToken,
) -> Result<Response, Error> {
    ensure!(
        xrpl_token.is_local(config.xrpl_multisig.clone()),
        Error::TokenNotLocal(XRPLTokenOrXrp::Issued(xrpl_token))
    );

    let chain_name_hash = token_id::chain_name_hash(config.chain_name.clone());
    let salt = token_id::currency_hash(&xrpl_token.currency);
    let token_id = token_id::linked_token_id(chain_name_hash, &xrpl_token.issuer, salt);

    match state::may_load_local_token_id(storage, &xrpl_token).change_context(Error::State)? {
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

    match state::may_load_xrpl_token(storage, &token_id).change_context(Error::State)? {
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
            state::save_xrpl_token(storage, &token_id, &xrpl_token).change_context(Error::State)?;
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
    match state::may_load_remote_token_id(storage, &xrpl_currency).change_context(Error::State)? {
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

    match state::may_load_xrpl_token(storage, &token_id).change_context(Error::State)? {
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

            state::save_xrpl_token(storage, &token_id, &xrpl_token).change_context(Error::State)?;
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
    if decimals > 50 {
        // TODO: Don't hardcode.
        bail!(Error::InvalidDecimals(decimals));
    }

    if chain == config.chain_name {
        bail!(Error::ForbiddenChain(chain));
    }

    match state::may_load_token_instance_decimals(storage, chain.clone(), token_id)
        .change_context(Error::State)?
    {
        Some(expected_decimals) => {
            ensure!(
                decimals == expected_decimals,
                Error::TokenDeployedDecimalsMismatch {
                    token_id,
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
    nexus_client: &nexus::Client,
    hub_message: interchain_token_service::HubMessage,
) -> Result<Response, Error> {
    let payload = hub_message.abi_encode();
    let cc_id = unique_cross_chain_id(nexus_client, config.chain_name.clone())?;
    let its_msg = construct_its_hub_message(config, cc_id, payload.clone())?;

    let router = Router::new(config.router.clone());
    Ok(Response::new()
        .add_messages(router.route(vec![its_msg.clone()]))
        .add_events(vec![
            XRPLGatewayEvent::RoutingIncoming {
                msg: its_msg.clone(),
            },
            XRPLGatewayEvent::ContractCalled {
                msg: its_msg,
                payload,
            },
        ]))
}

pub fn link_token(
    storage: &mut dyn Storage,
    config: &Config,
    nexus_client: &nexus::Client,
    token_id: TokenId,
    destination_chain: ChainNameRaw,
    link_token: LinkToken,
) -> Result<Response, Error> {
    ensure!(
        destination_chain != config.chain_name,
        Error::InvalidDestinationChain(destination_chain)
    );

    let xrpl_token = if token_id == config.xrp_token_id {
        XRPLTokenOrXrp::Xrp
    } else {
        let token =
            state::load_xrpl_token(storage, &token_id).change_context(Error::InvalidToken)?;
        register_token_instance(
            storage,
            config,
            token_id,
            destination_chain.clone(),
            XRPL_ISSUED_TOKEN_DECIMALS,
        )?;
        XRPLTokenOrXrp::Issued(token)
    };

    let its_msg =
        interchain_token_service::Message::LinkToken(interchain_token_service::LinkToken {
            token_id,
            token_manager_type: link_token.token_manager_type,
            source_token_address: nonempty::HexBinary::try_from(
                xrpl_token.serialize().as_bytes().to_vec(),
            )
            .change_context(Error::InvalidToken)?,
            destination_token_address: link_token.destination_token_address,
            params: link_token.params,
        });

    let hub_msg = interchain_token_service::HubMessage::SendToHub {
        destination_chain,
        message: its_msg,
    };
    route_hub_message(config, nexus_client, hub_msg)
}

pub fn deploy_remote_token(
    storage: &mut dyn Storage,
    config: &Config,
    nexus_client: &nexus::Client,
    token: XRPLTokenOrXrp,
    destination_chain: ChainNameRaw,
    token_metadata: TokenMetadata,
) -> Result<Response, Error> {
    ensure!(
        destination_chain != config.chain_name,
        Error::InvalidDestinationChain(destination_chain)
    );

    let (token_id, destination_decimals) = match &token {
        XRPLTokenOrXrp::Xrp => (config.xrp_token_id, token.decimals()),
        XRPLTokenOrXrp::Issued(xrpl_token) => (
            // load_token_id(storage, config.xrpl_multisig.clone(), &xrpl_token)?,
            state::load_local_token_id(storage, xrpl_token).change_context(Error::InvalidToken)?,
            token.decimals(),
        ),
    };

    register_token_instance(
        storage,
        config,
        token_id,
        destination_chain.clone(),
        destination_decimals,
    )?;

    let its_msg = interchain_token_service::Message::DeployInterchainToken(
        interchain_token_service::DeployInterchainToken {
            token_id,
            name: token_metadata.name,
            symbol: token_metadata.symbol,
            decimals: destination_decimals,
            minter: None,
        },
    );

    let hub_msg = interchain_token_service::HubMessage::SendToHub {
        destination_chain,
        message: its_msg,
    };
    route_hub_message(config, nexus_client, hub_msg)
}

fn generate_message_id(client: &nexus::Client) -> Result<[u8; 32], Error> {
    let nexus::query::TxHashAndNonceResponse { tx_hash, nonce } =
        client.tx_hash_and_nonce().change_context(Error::Nexus)?;

    Ok(Keccak256::digest(
        [
            Keccak256::digest(PREFIX_CROSS_CHAIN_ID).as_slice(),
            tx_hash.as_slice(),
            nonce.to_be_bytes().as_slice(),
        ]
        .concat(),
    )
    .into())
}

/// Query Nexus module in core to generate an unique cross chain id.
fn unique_cross_chain_id(
    client: &nexus::Client,
    chain_name: ChainName,
) -> Result<CrossChainId, Error> {
    let msg_id = generate_message_id(client)?;
    CrossChainId::new(chain_name, HexTxHash::new(msg_id)).change_context(Error::InvalidCrossChainId)
}

fn group_by_status<T>(
    verifier: &xrpl_voting_verifier::Client,
    msgs: Vec<T>,
) -> Result<Vec<(VerificationStatus, Vec<T>)>, Error>
where
    T: Into<XRPLMessage> + Clone,
{
    let msgs = check_for_duplicates(msgs, |m| {
        let msg: XRPLMessage = m.clone().into();
        msg.tx_id()
    })?;
    let msgs_status = fetch_msgs_status(verifier, msgs)?;
    let msgs_by_status = group_by_first(msgs_status);
    Ok(msgs_by_status)
}

fn fetch_msgs_status<T: Into<XRPLMessage> + Clone>(
    verifier: &xrpl_voting_verifier::Client,
    msgs: Vec<T>,
) -> Result<Vec<(VerificationStatus, T)>, Error> {
    Ok(verifier
        .messages_status(msgs.clone().into_iter().map(|m| m.into()).collect())
        .change_context(Error::MessageStatus)?
        .into_iter()
        .zip(msgs)
        .map(|(msg_status, msg)| (msg_status.status, msg))
        .collect::<Vec<_>>())
}

fn check_for_duplicates<T, F, Id>(msgs: Vec<T>, id_extractor: F) -> Result<Vec<T>, Error>
where
    T: Clone,
    Id: Eq + Hash + ToString,
    F: Fn(&T) -> Id,
{
    let duplicates: Vec<_> = msgs
        .iter()
        // the following two map instructions are separated on purpose
        // so the duplicate check is done on the typed id instead of just a string
        .map(&id_extractor)
        .duplicates()
        .map(|id| id.to_string())
        .collect();

    if !duplicates.is_empty() {
        return Err(Error::DuplicateMessageIds).attach_printable(duplicates.iter().join(", "));
    }

    Ok(msgs)
}

fn group_by_first<K, V>(msgs_with_status: impl IntoIterator<Item = (K, V)>) -> Vec<(K, Vec<V>)>
where
    K: Hash + Eq + Ord + Copy,
{
    msgs_with_status
        .into_iter()
        .into_group_map()
        .into_iter()
        // sort by verification status so the order of messages is deterministic
        .sorted_by_key(|(status, _)| *status)
        .collect()
}

// not all messages are verifiable, so it's better to only take a reference and allocate a vector on demand
// instead of requiring the caller to allocate a vector for every message
fn filter_verifiable_messages(
    status: VerificationStatus,
    msgs: &[XRPLMessage],
) -> Vec<XRPLMessage> {
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

fn filter_successful_messages<T: Clone>(status: VerificationStatus, msgs: &[T]) -> Vec<T> {
    if status == VerificationStatus::SucceededOnSourceChain {
        msgs.to_vec()
    } else {
        vec![]
    }
}

// not all messages are routable, so it's better to only take a reference and allocate a vector on demand
// instead of requiring the caller to allocate a vector for every message
fn filter_routable_messages(status: VerificationStatus, msgs: &[Message]) -> Vec<Message> {
    filter_successful_messages(status, msgs)
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

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axelar_core_std::nexus;
    use axelar_core_std::query::AxelarQueryMsg;
    use cosmwasm_std::testing::{MockQuerier, MockQuerierCustomHandlerResult};
    use cosmwasm_std::{ContractResult, QuerierWrapper, SystemResult};
    use router_api::ChainName;
    use serde::de::DeserializeOwned;
    use serde_json::json;

    pub fn reply_with_tx_hash_and_nonce<C>(
        tx_hash: [u8; 32],
        nonce: u64,
    ) -> impl Fn(&C) -> MockQuerierCustomHandlerResult
    where
        C: DeserializeOwned,
    {
        move |_| {
            SystemResult::Ok(ContractResult::Ok(
                json!({
                    "tx_hash": tx_hash,
                    "nonce": nonce,
                })
                .to_string()
                .as_bytes()
                .into(),
            ))
        }
    }

    #[test]
    pub fn unique_cross_chain_id() {
        let tx_hash = [0u8; 32];
        let nonce = 0;

        let querier: MockQuerier<AxelarQueryMsg> =
            MockQuerier::new(&[]).with_custom_handler(reply_with_tx_hash_and_nonce(tx_hash, nonce));

        let client: nexus::Client = client::CosmosClient::new(QuerierWrapper::new(&querier)).into();

        let chain_name = ChainName::from_str("xrpl").unwrap();
        let cc_id = super::unique_cross_chain_id(&client, chain_name).unwrap();
        goldie::assert!(cc_id.to_string());
    }
}
