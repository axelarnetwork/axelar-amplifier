use axelar_wasm_std::error::extend_err;
use cosmwasm_std::{to_json_binary, Binary, Storage};
use error_stack::Result;
use router_api::CrossChainId;

use crate::state::{self};

pub fn outgoing_messages<'a>(
    storage: &dyn Storage,
    cross_chain_ids: impl Iterator<Item = &'a CrossChainId>,
) -> Result<Binary, state::Error> {
    let msgs = cross_chain_ids
        .map(|id| state::may_load_outgoing_msg(storage, id))
        .fold(Ok(vec![]), accumulate_errs)?
        .into_iter()
        .filter_map(|msg_with_status| {
            if matches!(msg_with_status.status, state::MessageStatus::Approved) {
                Some(msg_with_status.msg)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    Ok(to_json_binary(&msgs).map_err(state::Error::from)?)
}

fn accumulate_errs(
    acc: Result<Vec<state::MessageWithStatus>, state::Error>,
    msg: std::result::Result<Option<state::MessageWithStatus>, state::Error>,
) -> Result<Vec<state::MessageWithStatus>, state::Error> {
    match (acc, msg) {
        (Ok(mut msgs), Ok(Some(msg))) => {
            msgs.push(msg);
            Ok(msgs)
        }
        (Ok(msgs), Ok(None)) => Ok(msgs),
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
    fn outgoing_messages_all_messages_present_returns_all_approved() {
        let mut deps = mock_dependencies();

        let messages = generate_messages();

        for message in messages.iter() {
            state::save_outgoing_msg(
                deps.as_mut().storage,
                message.cc_id.clone(),
                message.clone(),
            )
            .unwrap();
        }

        let ids = messages.iter().map(|msg| &msg.cc_id);

        let res = super::outgoing_messages(&deps.storage, ids).unwrap();
        let actual_messages: Vec<Message> = from_json(res).unwrap();
        assert_eq!(actual_messages, messages);
    }

    #[test]
    fn outgoing_messages_nothing_stored_returns_empty_list() {
        let deps = mock_dependencies();

        let messages = generate_messages();
        let ids = messages.iter().map(|msg| &msg.cc_id);

        let res = super::outgoing_messages(&deps.storage, ids).unwrap();
        let actual_messages: Vec<Message> = from_json(res).unwrap();
        assert!(actual_messages.is_empty());
    }

    #[test]
    fn outgoing_messages_only_partially_found_returns_partial_list() {
        let mut deps = mock_dependencies();

        let messages = generate_messages();

        state::save_outgoing_msg(
            deps.as_mut().storage,
            messages[1].cc_id.clone(),
            messages[1].clone(),
        )
        .unwrap();

        let ids = messages.iter().map(|msg| &msg.cc_id);

        let res = super::outgoing_messages(&deps.storage, ids).unwrap();
        let actual_messages: Vec<Message> = from_json(res).unwrap();
        assert_eq!(actual_messages, vec![messages[1].clone()]);
    }

    #[test]
    fn outgoing_messages_mixed_statuses_returns_only_approved() {
        let mut deps = mock_dependencies();

        let messages = generate_messages();

        state::save_outgoing_msg(
            deps.as_mut().storage,
            messages[0].cc_id.clone(),
            messages[0].clone(),
        )
        .unwrap();
        state::save_outgoing_msg(
            deps.as_mut().storage,
            messages[1].cc_id.clone(),
            messages[1].clone(),
        )
        .unwrap();
        state::update_msg_status(deps.as_mut().storage, messages[1].cc_id.clone()).unwrap();

        let ids = messages.iter().map(|msg| &msg.cc_id);

        let res = super::outgoing_messages(&deps.storage, ids).unwrap();
        let actual_messages: Vec<Message> = from_json(res).unwrap();
        assert_eq!(actual_messages, vec![messages[0].clone()]);
    }

    #[test]
    fn outgoing_messages_empty_input_returns_empty_list() {
        let deps = mock_dependencies();

        let res = super::outgoing_messages(&deps.storage, std::iter::empty()).unwrap();
        let actual_messages: Vec<Message> = from_json(res).unwrap();
        assert!(actual_messages.is_empty());
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
