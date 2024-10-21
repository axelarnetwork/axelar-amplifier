use std::iter;
use std::str::FromStr;

use axelar_core_std::nexus;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::token::GetToken;
use axelar_wasm_std::{address, FnExt, IntoContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    Addr, BankMsg, Coin, CosmosMsg, DepsMut, Event, HexBinary, MessageInfo, QuerierWrapper,
    Response, Storage,
};
use error_stack::{bail, ensure, report, ResultExt};
use itertools::Itertools;
use router_api::client::Router;
use router_api::{Address, ChainName, CrossChainId, Message};
use sha3::{Digest, Keccak256};

use crate::clients::external;
use crate::events::AxelarnetGatewayEvent;
use crate::state::Config;
use crate::{state, AxelarExecutableMsg};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to save executable message")]
    SaveExecutableMessage,
    #[error("failed to access routable message")]
    RoutableMessageAccess,
    #[error("message with ID {0} does not match the expected message")]
    MessageMismatch(CrossChainId),
    #[error("failed to mark message with ID {0} as executed")]
    MarkExecuted(CrossChainId),
    #[error("expected destination chain {expected}, got {actual}")]
    InvalidDestination {
        expected: ChainName,
        actual: ChainName,
    },
    #[error("failed to generate cross chain id")]
    CrossChainIdGeneration,
    #[error("unable to save the message before routing")]
    SaveRoutableMessage,
    #[error("invalid cross-chain id")]
    InvalidCrossChainId,
    #[error("unable to generate event index")]
    EventIndex,
    #[error("invalid source address {0}")]
    InvalidSourceAddress(Addr),
    #[error("invalid destination address {0}")]
    InvalidDestinationAddress(String),
    #[error("failed to query the nexus module")]
    Nexus,
    #[error("nonce from the nexus module overflowed u32")]
    NonceOverflow,
    #[error("invalid token received")]
    InvalidToken,
    #[error("invalid routing destination")]
    InvalidRoutingDestination,
    #[error("failed to convert the nexus message for the router")]
    InvalidNexusMessageForRouter,
}

#[cw_serde]
pub struct CallContractData {
    pub destination_chain: ChainName,
    pub destination_address: Address,
    pub payload: HexBinary,
}

impl CallContractData {
    pub fn to_message(&self, id: CrossChainId, source_address: Address) -> Message {
        Message {
            cc_id: id,
            source_address,
            destination_chain: self.destination_chain.clone(),
            destination_address: self.destination_address.clone(),
            payload_hash: Keccak256::digest(self.payload.as_slice()).into(),
        }
    }
}

enum RoutingDestination {
    Nexus,
    Router,
    /// Messages that are intended for contracts on Axelar
    This,
}

type Result<T> = error_stack::Result<T, Error>;
type CosmosMsgWithEvent = (Vec<CosmosMsg<nexus::execute::Message>>, Vec<Event>);

pub fn call_contract(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    info: MessageInfo,
    call_contract: CallContractData,
) -> Result<Response<nexus::execute::Message>> {
    let Config { chain_name, .. } = state::load_config(storage);

    let client: nexus::Client = client::CosmosClient::new(querier).into();

    let id = unique_cross_chain_id(&client, chain_name.clone())?;
    let source_address = Address::from_str(info.sender.as_str())
        .change_context(Error::InvalidSourceAddress(info.sender.clone()))?;
    let msg = call_contract.to_message(id, source_address);

    state::save_unique_routable_msg(storage, &msg.cc_id, &msg)
        .inspect_err(|err| panic_if_already_exists(err, &msg.cc_id))
        .change_context(Error::SaveRoutableMessage)?;

    let token = info.single_token().change_context(Error::InvalidToken)?;
    let event = AxelarnetGatewayEvent::ContractCalled {
        msg: msg.clone(),
        payload: call_contract.payload,
        token: token.clone(),
    };

    route_messages(storage, querier, info.sender, vec![msg]).map(|res| res.add_event(event.into()))
}

pub fn route_messages(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    sender: Addr,
    msgs: Vec<Message>,
) -> Result<Response<nexus::execute::Message>> {
    let Config {
        chain_name,
        router,
        nexus,
    } = state::load_config(storage);

    let router = Router::new(router);
    let client: nexus::Client = client::CosmosClient::new(querier).into();

    // Router-sent messages are assumed pre-verified and routable
    // Otherwise, only route routable messages instantiated from CallContract
    let msgs = if sender != router.address {
        msgs.into_iter()
            .unique()
            .map(|msg| try_load_routable_msg(storage, msg))
            .filter_map_ok(|msg| msg)
            .try_collect()?
    } else {
        msgs
    };

    msgs.into_iter()
        .group_by(|msg| msg.destination_chain.to_owned())
        .into_iter()
        .try_fold(Response::new(), |acc, (dest_chain, msgs)| {
            let (messages, events) = match determine_routing_destination(
                &sender,
                &client,
                &dest_chain,
                &router.address,
                &chain_name,
            )? {
                RoutingDestination::This => {
                    prepare_msgs_for_execution(storage, chain_name.clone(), msgs.collect())
                }
                RoutingDestination::Nexus => {
                    route_messages_to_nexus(&client, &nexus, msgs.collect())
                }
                RoutingDestination::Router => route_to_router(&router, msgs.collect()),
            }?;

            Ok(acc.add_messages(messages).add_events(events))
        })
}

pub fn execute(
    deps: DepsMut,
    cc_id: CrossChainId,
    payload: HexBinary,
) -> Result<Response<nexus::execute::Message>> {
    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();
    let msg = state::mark_as_executed(
        deps.storage,
        &cc_id,
        ensure_same_payload_hash(&payload_hash),
    )
    .change_context(Error::MarkExecuted(cc_id.clone()))?;

    let executable_msg = AxelarExecutableMsg {
        cc_id,
        source_address: msg.source_address.clone(),
        payload,
    };

    let destination = address::validate_cosmwasm_address(deps.api, &msg.destination_address)
        .change_context(Error::InvalidDestinationAddress(
            msg.destination_address.to_string(),
        ))?;

    Response::new()
        .add_message(external::Client::new(deps.querier, &destination).execute(executable_msg))
        .add_event(AxelarnetGatewayEvent::MessageExecuted { msg }.into())
        .then(Ok)
}

pub fn route_messages_from_nexus(
    storage: &dyn Storage,
    msgs: Vec<nexus::execute::Message>,
) -> Result<Response<nexus::execute::Message>> {
    let msgs: Vec<_> = msgs
        .into_iter()
        .map(router_api::Message::try_from)
        .collect::<error_stack::Result<Vec<_>, _>>()
        .change_context(Error::InvalidNexusMessageForRouter)?;

    let router = Router::new(state::load_config(storage).router);

    Ok(Response::new().add_messages(router.route(msgs)))
}

fn ensure_same_payload_hash(
    payload_hash: &[u8; 32],
) -> impl FnOnce(&Message) -> core::result::Result<(), state::Error> + '_ {
    |msg| {
        if *payload_hash != msg.payload_hash {
            return Err(state::Error::PayloadHashMismatch);
        }

        Ok(())
    }
}

fn panic_if_already_exists(err: &state::Error, cc_id: &CrossChainId) {
    if matches!(err, state::Error::MessageAlreadyExists(..)) {
        panic!(
            "violated invariant: message with ID {0} already exists",
            cc_id
        )
    }
}

// Because the messages came from the router, we can assume they are already verified
fn prepare_msgs_for_execution(
    store: &mut dyn Storage,
    chain_name: ChainName,
    msgs: Vec<Message>,
) -> Result<CosmosMsgWithEvent> {
    for msg in msgs.iter() {
        ensure!(
            chain_name == msg.destination_chain,
            Error::InvalidDestination {
                expected: chain_name,
                actual: msg.destination_chain.clone()
            }
        );

        state::save_executable_msg(store, &msg.cc_id, msg.clone())
            .change_context(Error::SaveExecutableMessage)?;
    }

    Ok((
        vec![],
        msgs.into_iter()
            .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into())
            .collect(),
    ))
}

/// Route messages to the router, ignore unknown messages.
fn route_to_router(
    router: &Router<nexus::execute::Message>,
    msgs: Vec<Message>,
) -> Result<CosmosMsgWithEvent> {
    Ok((
        router.route(msgs.clone()).into_iter().collect(),
        msgs.into_iter()
            .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into())
            .collect(),
    ))
}

/// Verify that the message is stored and matches the one we're trying to route. Returns Ok(None) if
/// the message is not stored.
fn try_load_routable_msg(store: &mut dyn Storage, msg: Message) -> Result<Option<Message>> {
    let stored_msg = state::may_load_routable_msg(store, &msg.cc_id)
        .change_context(Error::RoutableMessageAccess)?;

    match stored_msg {
        Some(stored_msg) if stored_msg != msg => {
            bail!(Error::MessageMismatch(msg.cc_id.clone()))
        }
        Some(stored_msg) => Ok(Some(stored_msg)),
        None => Ok(None),
    }
}

/// Query Nexus module in core to generate an unique cross chain id.
fn unique_cross_chain_id(client: &nexus::Client, chain_name: ChainName) -> Result<CrossChainId> {
    let nexus::query::TxHashAndNonceResponse { tx_hash, nonce } =
        client.tx_hash_and_nonce().change_context(Error::Nexus)?;

    CrossChainId::new(
        chain_name,
        HexTxHashAndEventIndex::new(
            tx_hash,
            u32::try_from(nonce).change_context(Error::NonceOverflow)?,
        ),
    )
    .change_context(Error::InvalidCrossChainId)
}

/// Query Nexus module in core to decide should route message to core
fn determine_routing_destination(
    sender: &Addr,
    client: &nexus::Client,
    dest_chain: &ChainName,
    router: &Addr,
    this_chain: &ChainName,
) -> Result<RoutingDestination> {
    if client
        .is_chain_registered(dest_chain)
        .change_context(Error::Nexus)?
    {
        RoutingDestination::Nexus
    } else if sender == router {
        ensure!(dest_chain == this_chain, Error::InvalidRoutingDestination);
        RoutingDestination::This
    } else {
        RoutingDestination::Router
    }
    .then(Ok)
}

/// Route message to the Nexus module
fn route_to_nexus(
    client: &nexus::Client,
    nexus: &Addr,
    msg: Message,
    token: Option<Coin>,
) -> Result<Vec<CosmosMsg<nexus::execute::Message>>> {
    let msg: nexus::execute::Message = (msg, token.clone()).into();

    token
        .map(|token| BankMsg::Send {
            to_address: nexus.to_string(),
            amount: vec![token],
        })
        .map(Into::into)
        .into_iter()
        .chain(iter::once(client.route_message(msg)))
        .collect::<Vec<_>>()
        .then(Ok)
}

pub fn route_messages_to_nexus(
    client: &nexus::Client,
    nexus: &Addr,
    msgs: Vec<Message>,
) -> Result<CosmosMsgWithEvent> {
    let nexus_msgs = msgs
        .clone()
        .into_iter()
        .map(|msg| route_to_nexus(client, nexus, msg, None))
        .collect::<Result<Vec<_>>>()?
        .then(|msgs| msgs.concat());

    Ok((
        nexus_msgs,
        msgs.into_iter()
            .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into())
            .collect(),
    ))
}
