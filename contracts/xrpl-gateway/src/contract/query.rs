use axelar_wasm_std::error::extend_err;
use axelar_wasm_std::nonempty;
use cosmwasm_std::{to_json_binary, Addr, Binary, Storage};
use error_stack::Result;
use interchain_token_service::TokenId;
use router_api::{ChainNameRaw, CrossChainId, Message};
use xrpl_types::msg::{XRPLCallContractMessage, XRPLInterchainTransferMessage};

use super::{execute, Error};
use crate::state::{self, Config};
use crate::token_id;

pub fn outgoing_messages<'a>(
    storage: &dyn Storage,
    cross_chain_ids: impl Iterator<Item = &'a CrossChainId>,
) -> Result<Binary, state::Error> {
    let msgs = cross_chain_ids
        .map(|id| state::load_outgoing_message(storage, id))
        .fold(Ok(vec![]), accumulate_errs)?;

    Ok(to_json_binary(&msgs).map_err(state::Error::from)?)
}

pub fn xrpl_token(storage: &dyn Storage, token_id: TokenId) -> Result<Binary, state::Error> {
    let xrpl_token = state::load_xrpl_token(storage, &token_id)?;
    Ok(to_json_binary(&xrpl_token).map_err(state::Error::from)?)
}

pub fn xrp_token_id(storage: &dyn Storage) -> Result<Binary, state::Error> {
    let config = state::load_config(storage);
    let token_id = config.xrp_token_id;
    Ok(to_json_binary(&token_id).map_err(state::Error::from)?)
}

pub fn linked_token_id(
    storage: &dyn Storage,
    deployer: Addr,
    salt: [u8; 32],
) -> Result<Binary, state::Error> {
    let config = state::load_config(storage);
    let chain_name_hash = token_id::chain_name_hash(config.chain_name);
    let linked_token_id = token_id::linked_token_id(chain_name_hash, deployer, salt);
    Ok(to_json_binary(&linked_token_id).map_err(state::Error::from)?)
}

pub fn token_instance_decimals(
    storage: &dyn Storage,
    chain_name: ChainNameRaw,
    token_id: TokenId,
) -> Result<Binary, state::Error> {
    let decimals = state::load_token_instance_decimals(storage, chain_name, token_id)?;
    Ok(to_json_binary(&decimals).map_err(state::Error::from)?)
}

pub fn translate_to_interchain_transfer(
    storage: &dyn Storage,
    config: &Config,
    message: &XRPLInterchainTransferMessage,
    payload: Option<nonempty::HexBinary>,
) -> Result<Binary, Error> {
    let interchain_transfer =
        execute::translate_to_interchain_transfer(storage, config, message, payload)?;
    Ok(to_json_binary(&interchain_transfer).map_err(Error::from)?)
}

pub fn translate_to_call_contract(
    storage: &dyn Storage,
    config: &Config,
    message: &XRPLCallContractMessage,
) -> Result<Binary, Error> {
    let call_contract = execute::translate_to_call_contract(storage, config, message)?;
    Ok(to_json_binary(&call_contract).map_err(Error::from)?)
}

fn accumulate_errs(
    acc: Result<Vec<Message>, state::Error>,
    msg: Result<Message, state::Error>,
) -> Result<Vec<Message>, state::Error> {
    match (acc, msg) {
        (Ok(mut acc), Ok(msg)) => {
            acc.push(msg);
            Ok(acc)
        }
        (Err(report), Ok(_)) => Err(report),
        (acc, Err(msg_err)) => extend_err(acc, msg_err),
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::from_json;
    use cosmwasm_std::testing::mock_dependencies;
    use router_api::{CrossChainId, Message};

    use crate::state;

    #[test]
    fn outgoing_messages_all_messages_present_returns_all() {
        let mut deps = mock_dependencies();

        let messages = generate_messages();

        for message in messages.iter() {
            state::save_outgoing_message(deps.as_mut().storage, &message.cc_id, message).unwrap();
        }

        let ids = messages.iter().map(|msg| &msg.cc_id);

        let res = super::outgoing_messages(&deps.storage, ids).unwrap();
        let actual_messages: Vec<Message> = from_json(res).unwrap();
        assert_eq!(actual_messages, messages);
    }

    #[test]
    fn outgoing_messages_nothing_stored_returns_not_found_error() {
        let deps = mock_dependencies();

        let messages = generate_messages();
        let ids = messages.iter().map(|msg| &msg.cc_id);

        let res = super::outgoing_messages(&deps.storage, ids);

        assert!(res.is_err());
        assert_eq!(res.unwrap_err().current_frames().len(), messages.len());
    }

    #[test]
    fn outgoing_messages_only_partially_found_returns_not_found_error() {
        let mut deps = mock_dependencies();

        let messages = generate_messages();

        state::save_outgoing_message(deps.as_mut().storage, &messages[1].cc_id, &messages[1])
            .unwrap();

        let ids = messages.iter().map(|msg| &msg.cc_id);

        let res = super::outgoing_messages(&deps.storage, ids);

        assert!(res.is_err());
        assert_eq!(res.unwrap_err().current_frames().len(), messages.len() - 1);
    }

    fn generate_messages() -> Vec<Message> {
        vec![
            Message {
                cc_id: CrossChainId::new("chain1", "id1").unwrap(),
                destination_address: "addr1".parse().unwrap(),
                destination_chain: "chain2".parse().unwrap(),
                source_address: "addr2".parse().unwrap(),
                payload_hash: [0; 32],
            },
            Message {
                cc_id: CrossChainId::new("chain2", "id2").unwrap(),
                destination_address: "addr3".parse().unwrap(),
                destination_chain: "chain3".parse().unwrap(),
                source_address: "addr4".parse().unwrap(),
                payload_hash: [1; 32],
            },
            Message {
                cc_id: CrossChainId::new("chain3", "id3").unwrap(),
                destination_address: "addr5".parse().unwrap(),
                destination_chain: "chain4".parse().unwrap(),
                source_address: "addr6".parse().unwrap(),
                payload_hash: [2; 32],
            },
        ]
    }
}
