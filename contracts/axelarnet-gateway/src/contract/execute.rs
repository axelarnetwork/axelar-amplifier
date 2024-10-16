use std::iter;
use std::str::FromStr;

use axelar_core_std::nexus;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::token::GetToken;
use axelar_wasm_std::{address, FnExt, IntoContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    Addr, BankMsg, Coin, DepsMut, HexBinary, MessageInfo, QuerierWrapper, Response, Storage,
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
    #[error("failed to access executable message")]
    ExecutableMessageAccess,
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
}

type Result<T> = error_stack::Result<T, Error>;

pub fn call_contract(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    info: MessageInfo,
    call_contract: CallContractData,
) -> Result<Response<nexus::execute::Message>> {
    let Config {
        router,
        chain_name,
        nexus,
    } = state::load_config(storage);

    let client: nexus::Client = client::CosmosClient::new(querier).into();

    let id = unique_cross_chain_id(&client, chain_name)?;
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

    let res = match determine_routing_destination(&client, &msg.destination_chain)? {
        RoutingDestination::Nexus => route_to_nexus(&client, nexus, msg, token)?,
        RoutingDestination::Router if token.is_none() => {
            route_to_router(storage, &Router::new(router), vec![msg])?
        }
        _ => bail!(Error::InvalidRoutingDestination),
    }
    .add_event(event.into());

    Ok(res)
}

pub fn route_messages(
    storage: &mut dyn Storage,
    sender: Addr,
    msgs: Vec<Message>,
) -> Result<Response<nexus::execute::Message>> {
    let Config {
        chain_name, router, ..
    } = state::load_config(storage);
    let router = Router::new(router);

    if sender == router.address {
        Ok(prepare_msgs_for_execution(storage, chain_name, msgs)?)
    } else {
        // Messages initiated via call contract can be routed again
        Ok(route_to_router(storage, &router, msgs)?)
    }
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
) -> Result<Response<nexus::execute::Message>> {
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

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into()),
    ))
}

/// Route messages to the router, ignore unknown messages.
fn route_to_router(
    store: &mut dyn Storage,
    router: &Router<nexus::execute::Message>,
    msgs: Vec<Message>,
) -> Result<Response<nexus::execute::Message>> {
    let msgs: Vec<_> = msgs
        .into_iter()
        .unique()
        .map(|msg| try_load_executable_msg(store, msg))
        .filter_map_ok(|msg| msg)
        .try_collect()?;

    Ok(Response::new()
        .add_messages(router.route(msgs.clone()))
        .add_events(
            msgs.into_iter()
                .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into()),
        ))
}

/// Verify that the message is stored and matches the one we're trying to route. Returns Ok(None) if
/// the message is not stored.
fn try_load_executable_msg(store: &mut dyn Storage, msg: Message) -> Result<Option<Message>> {
    let stored_msg = state::may_load_routable_msg(store, &msg.cc_id)
        .change_context(Error::ExecutableMessageAccess)?;

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
    client: &nexus::Client,
    name: &ChainName,
) -> Result<RoutingDestination> {
    let dest = match client
        .is_chain_registered(name)
        .change_context(Error::Nexus)?
    {
        true => RoutingDestination::Nexus,
        false => RoutingDestination::Router,
    };

    Ok(dest)
}

/// Route message to the Nexus module
fn route_to_nexus(
    client: &nexus::Client,
    nexus: Addr,
    msg: Message,
    token: Option<Coin>,
) -> Result<Response<nexus::execute::Message>> {
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
        .then(|msgs| Response::new().add_messages(msgs))
        .then(Ok)
}
