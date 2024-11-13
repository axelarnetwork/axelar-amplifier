use axelar_wasm_std::error::extend_err;
use cosmwasm_std::{to_json_binary, Binary, Storage};
use error_stack::Result;
use interchain_token_service::TokenId;
use router_api::{CrossChainId, Message};

use crate::state;

pub fn outgoing_messages<'a>(
    storage: &dyn Storage,
    cross_chain_ids: impl Iterator<Item = &'a CrossChainId>,
) -> Result<Binary, state::Error> {
    let msgs = cross_chain_ids
        .map(|id| state::load_outgoing_message(storage, id))
        .fold(Ok(vec![]), accumulate_errs)?;

    Ok(to_json_binary(&msgs).map_err(state::Error::from)?)
}

pub fn token_info(
    storage: &dyn Storage,
    token_id: TokenId,
) -> Result<Binary, state::Error> {
    let token_info = state::load_token_info(storage, &token_id)?;
    Ok(to_json_binary(&token_info).map_err(state::Error::from)?)
}

fn accumulate_errs(
    acc: Result<Vec<Message>, state::Error>,
    msg: std::result::Result<Message, state::Error>,
) -> Result<Vec<Message>, state::Error> {
    match (acc, msg) {
        (Ok(mut acc), Ok(msg)) => {
            acc.push(msg);
            Ok(acc)
        }
        (Err(report), Ok(_)) => Err(report),
        (acc, Err(msg_err)) => extend_err(acc, msg_err.into()),
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
