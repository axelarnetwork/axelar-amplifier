use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::nonempty;
use cosmwasm_std::{BankMsg, HexBinary, MessageInfo, QuerierWrapper, Response, Storage};
use error_stack::{bail, ResultExt};
use router_api::{Address, ChainName};
use sha3::{Digest, Keccak256};

use crate::error::ContractError;
use crate::state::load_config;
use crate::{nexus, state};

type Result<T> = error_stack::Result<T, ContractError>;

pub fn call_contract_with_token(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    info: MessageInfo,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response<nexus::Message>> {
    let config = load_config(storage)?;
    let axelarnet_gateway: axelarnet_gateway::Client =
        client::Client::new(querier, config.axelar_gateway).into();
    let source_address: Address = info
        .sender
        .into_string()
        .parse()
        .expect("invalid sender address");
    let token = match info.funds.as_slice() {
        [token] => token.clone(),
        _ => bail!(ContractError::InvalidToken(info.funds)),
    };
    // TODO: Retrieve the actual tx hash and event index from core, since cosmwasm doesn't provide it. Use the all zeros as the placeholder in the meantime.
    let tx_hash = [0; 32];
    let event_index = 0u32;
    let id = HexTxHashAndEventIndex::new(tx_hash, event_index);

    // send the token to the nexus module account
    let bank_transfer_msg = BankMsg::Send {
        to_address: config.nexus.to_string(),
        amount: vec![token.clone()],
    };
    let msg = nexus::Message {
        source_chain: axelarnet_gateway
            .chain_name()
            .change_context(ContractError::AxelarnetGateway)?
            .into(),
        source_address,
        destination_chain,
        destination_address,
        payload_hash: Keccak256::digest(payload.as_slice()).into(),
        source_tx_id: tx_hash
            .to_vec()
            .try_into()
            .expect("tx hash must not be empty"),
        source_tx_index: event_index.into(),
        id: nonempty::String::from(id).into(),
        token: Some(token),
    };

    Ok(Response::new()
        .add_message(bank_transfer_msg)
        .add_message(msg))
}

pub fn route_to_router(
    storage: &dyn Storage,
    msgs: Vec<nexus::Message>,
) -> Result<Response<nexus::Message>> {
    let msgs: Vec<_> = msgs
        .into_iter()
        .map(router_api::Message::try_from)
        .collect::<Result<Vec<_>>>()?;
    let router = router_api::client::Router {
        address: state::load_config(storage)?.router,
    };

    Ok(Response::new().add_messages(router.route(msgs)))
}

pub fn route_to_nexus(
    storage: &mut dyn Storage,
    msgs: Vec<router_api::Message>,
) -> Result<Response<nexus::Message>> {
    let msgs = msgs
        .into_iter()
        .filter_map(|msg| match state::is_message_routed(storage, &msg.cc_id) {
            Ok(true) => None,
            Ok(false) => Some(Ok(msg)),
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<Vec<_>>>()?;

    msgs.iter()
        .try_for_each(|msg| state::set_message_routed(storage, &msg.cc_id))?;

    let msgs: Vec<nexus::Message> = msgs.into_iter().map(Into::into).collect();

    Ok(Response::new().add_messages(msgs))
}
