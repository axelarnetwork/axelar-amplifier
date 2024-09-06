use axelar_wasm_std::IntoContractError;
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{self, load_config, load_its_address};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("unknown chain {0}")]
    UnknownChain(ChainName),
    #[error("unknown its address {0}")]
    UnknownItsAddress(Address),
    #[error("failed to decode payload")]
    InvalidPayload,
    #[error("invalid message type")]
    InvalidMessageType,
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
            let destination_address = load_its_address(deps.storage, &destination_chain)
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

fn to_chain_name(chain: &ChainNameRaw) -> ChainName {
    ChainName::try_from(chain.as_ref()).expect("invalid chain name")
}

fn ensure_its_source_address(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    source_address: &Address,
) -> Result<(), Error> {
    let source_chain = to_chain_name(source_chain);
    let its_source_address = load_its_address(storage, &source_chain)
        .change_context_lazy(|| Error::UnknownChain(source_chain.clone()))?;

    ensure!(
        source_address == &its_source_address,
        Error::UnknownItsAddress(source_address.clone())
    );

    Ok(())
}

fn send_to_destination(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let config = load_config(storage);

    let gateway: axelarnet_gateway::Client =
        client::Client::new(querier, &config.axelarnet_gateway).into();

    let call_contract_msg = gateway.call_contract(destination_chain, destination_address, payload);

    Ok(Response::new().add_message(call_contract_msg))
}

pub fn register_its_address(
    deps: DepsMut,
    chain: ChainName,
    address: Address,
) -> Result<Response, Error> {
    state::save_its_address(deps.storage, &chain, &address)
        .change_context_lazy(|| Error::UnknownChain(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsAddressRegistered { chain, address }.into()))
}

pub fn deregister_its_address(deps: DepsMut, chain: ChainName) -> Result<Response, Error> {
    state::remove_its_address(deps.storage, &chain);

    Ok(Response::new().add_event(Event::ItsAddressDeregistered { chain }.into()))
}
