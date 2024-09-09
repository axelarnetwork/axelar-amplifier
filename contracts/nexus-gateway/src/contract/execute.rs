use axelar_core_std::nexus;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::nonempty;
use cosmwasm_std::{BankMsg, HexBinary, MessageInfo, QuerierWrapper, Response, Storage};
use error_stack::{bail, ResultExt};
use router_api::{Address, ChainName};
use sha3::{Digest, Keccak256};

use crate::error::Error;
use crate::state;
use crate::state::load_config;

type Result<T> = error_stack::Result<T, Error>;

pub fn call_contract_with_token(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    info: MessageInfo,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response<nexus::execute::Message>> {
    let config = load_config(storage)?;
    let axelarnet_gateway: axelarnet_gateway::Client =
        client::ContractClient::new(querier, &config.axelarnet_gateway).into();
    let source_address: Address = info
        .sender
        .into_string()
        .parse()
        .expect("invalid sender address");
    let token = match info.funds.as_slice() {
        [token] => token.clone(),
        _ => bail!(Error::InvalidToken(info.funds)),
    };

    let client: nexus::Client = client::Client::new(querier).into();
    let tx_hash_and_nonce = client.tx_hash_and_nonce().change_context(Error::Nexus)?;
    let id = HexTxHashAndEventIndex::new(
        tx_hash_and_nonce.tx_hash,
        u32::try_from(tx_hash_and_nonce.nonce).change_context(Error::NonceOverflow)?,
    );

    // send the token to the nexus module account
    let bank_transfer_msg = BankMsg::Send {
        to_address: config.nexus.to_string(),
        amount: vec![token.clone()],
    };
    let msg = nexus::execute::Message {
        source_chain: axelarnet_gateway
            .chain_name()
            .change_context(Error::AxelarnetGateway)?
            .into(),
        source_address,
        destination_chain,
        destination_address,
        payload_hash: Keccak256::digest(payload.as_slice()).into(),
        source_tx_id: tx_hash_and_nonce
            .tx_hash
            .to_vec()
            .try_into()
            .expect("tx hash must not be empty"),
        source_tx_index: tx_hash_and_nonce.nonce,
        id: nonempty::String::from(id).into(),
        token: Some(token),
    };

    Ok(Response::new()
        .add_message(bank_transfer_msg)
        .add_message(client.route_message(msg)))
}

pub fn route_to_router(
    storage: &dyn Storage,
    msgs: Vec<nexus::execute::Message>,
) -> Result<Response<nexus::execute::Message>> {
    let msgs: Vec<_> = msgs
        .into_iter()
        .map(router_api::Message::try_from)
        .collect::<error_stack::Result<Vec<_>, _>>()
        .change_context(Error::InvalidNexusMessageForRouter)?;

    let router = router_api::client::Router::new(state::load_config(storage)?.router);

    Ok(Response::new().add_messages(router.route(msgs)))
}

pub fn route_to_nexus(
    storage: &mut dyn Storage,
    msgs: Vec<router_api::Message>,
) -> Result<Response<nexus::execute::Message>> {
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

    let msgs: Vec<nexus::execute::Message> = msgs.into_iter().map(Into::into).collect();

    Ok(Response::new().add_messages(msgs))
}
