use axelar_wasm_std::error::extend_err;
use cosmwasm_std::Storage;
use error_stack::{report, Result, ResultExt};
use router_api::{CrossChainId, Message};

use crate::contract::Error;
use crate::state;

pub fn get_outgoing_messages(
    storage: &dyn Storage,
    cross_chain_ids: Vec<CrossChainId>,
) -> Result<Vec<Message>, Error> {
    cross_chain_ids
        .into_iter()
        .map(|id| try_load_msg(storage, id))
        .fold(Ok(vec![]), accumulate_errs)
}

fn try_load_msg(storage: &dyn Storage, id: CrossChainId) -> Result<Message, Error> {
    state::may_load_outgoing_msg(storage, id.clone())
        .change_context(Error::InvalidStoreAccess)
        .transpose()
        .unwrap_or(Err(report!(Error::MessageNotFound(id))))
}

fn accumulate_errs(
    acc: Result<Vec<Message>, Error>,
    msg: Result<Message, Error>,
) -> Result<Vec<Message>, Error> {
    match (acc, msg) {
        (Ok(mut acc), Ok(msg)) => {
            acc.push(msg);
            Ok(acc)
        }
        (Err(acc), Ok(_)) => Err(acc),
        (acc, Err(msg_err)) => extend_err(acc, msg_err),
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::mock_dependencies;
    use router_api::{CrossChainId, Message};

    use crate::state;

    #[test]
    fn get_outgoing_messages_all_messages_present_returns_all() {
        let mut deps = mock_dependencies();

        let messages = generate_messages();

        for message in messages.iter() {
            state::save_outgoing_msg(deps.as_mut().storage, message.cc_id.clone(), message)
                .unwrap();
        }

        let ids = messages.iter().map(|msg| msg.cc_id.clone()).collect();

        let res = super::get_outgoing_messages(&deps.storage, ids).unwrap();
        assert_eq!(res, messages);
    }

    #[test]
    fn get_outgoing_messages_nothing_stored_returns_not_found_error() {
        let deps = mock_dependencies();

        let messages = generate_messages();
        let ids = messages.iter().map(|msg| msg.cc_id.clone()).collect();

        let res = super::get_outgoing_messages(&deps.storage, ids);

        assert!(res.is_err());
        assert_eq!(res.unwrap_err().current_frames().len(), messages.len());
    }

    #[test]
    fn get_outgoing_messages_only_partially_found_returns_not_found_error() {
        let mut deps = mock_dependencies();

        let messages = generate_messages();

        state::save_outgoing_msg(
            deps.as_mut().storage,
            messages[1].cc_id.clone(),
            &messages[1],
        )
        .unwrap();

        let ids = messages.iter().map(|msg| msg.cc_id.clone()).collect();

        let res = super::get_outgoing_messages(&deps.storage, ids);

        assert!(res.is_err());
        assert_eq!(res.unwrap_err().current_frames().len(), messages.len() - 1);
    }

    fn generate_messages() -> Vec<Message> {
        vec![
            Message {
                cc_id: CrossChainId {
                    chain: "chain1".parse().unwrap(),
                    id: "id1".parse().unwrap(),
                },
                destination_address: "addr1".parse().unwrap(),
                destination_chain: "chain2".parse().unwrap(),
                source_address: "addr2".parse().unwrap(),
                payload_hash: [0; 32],
            },
            Message {
                cc_id: CrossChainId {
                    chain: "chain2".parse().unwrap(),
                    id: "id2".parse().unwrap(),
                },
                destination_address: "addr3".parse().unwrap(),
                destination_chain: "chain3".parse().unwrap(),
                source_address: "addr4".parse().unwrap(),
                payload_hash: [1; 32],
            },
            Message {
                cc_id: CrossChainId {
                    chain: "chain3".parse().unwrap(),
                    id: "id3".parse().unwrap(),
                },
                destination_address: "addr5".parse().unwrap(),
                destination_chain: "chain4".parse().unwrap(),
                source_address: "addr6".parse().unwrap(),
                payload_hash: [2; 32],
            },
        ]
    }
}
