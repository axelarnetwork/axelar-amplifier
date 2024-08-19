use axelar_wasm_std::counter::Counter;
use axelar_wasm_std::{FnExt, IntoContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, Storage};
use cw_storage_plus::{Item, Map};
use router_api::{ChainName, CrossChainId, Message};

#[cw_serde]
pub struct Config {
    pub chain_name: ChainName,
    pub router: Addr,
}

#[cw_serde]
pub enum MessageStatus {
    Approved,
    Executed,
}

#[cw_serde]
pub struct MessageWithStatus {
    pub msg: Message,
    pub status: MessageStatus,
}

const CONFIG_NAME: &str = "config";
const CONFIG: Item<Config> = Item::new(CONFIG_NAME);

const SENT_MESSAGE_COUNTER_NAME: &str = "sent_message_counter";
const SENT_MESSAGE_COUNTER: Counter<u32> = Counter::new(SENT_MESSAGE_COUNTER_NAME);

const SENT_MESSAGES_NAME: &str = "sent_messages";
const SENT_MESSAGES: Map<CrossChainId, Message> = Map::new(SENT_MESSAGES_NAME);

const RECEIVED_MESSAGES_NAME: &str = "received_messages";
const RECEIVED_MESSAGES: Map<CrossChainId, MessageWithStatus> = Map::new(RECEIVED_MESSAGES_NAME);

#[derive(thiserror::Error, Debug, PartialEq, IntoContractError)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("gateway got into an invalid state, its config is missing")]
    MissingConfig,
    #[error("message with ID {0} mismatches with the stored one")]
    MessageMismatch(CrossChainId),
    #[error("message with ID {0} not found")]
    MessageNotFound(CrossChainId),
    #[error("message with ID {0} not approved")]
    MessageNotApproved(CrossChainId),
    #[error("message with ID {0} already executed")]
    MessageAlreadyExecuted(CrossChainId),
    #[error("sent message with ID {0} already exists")]
    MessageAlreadyExists(CrossChainId),
}

pub fn save_config(storage: &mut dyn Storage, value: &Config) -> Result<(), Error> {
    CONFIG.save(storage, value).map_err(Error::from)
}

pub fn load_config(storage: &dyn Storage) -> Result<Config, Error> {
    CONFIG
        .may_load(storage)
        .map_err(Error::from)?
        .ok_or(Error::MissingConfig)
}

pub fn save_sent_msg(
    storage: &mut dyn Storage,
    key: CrossChainId,
    msg: &Message,
) -> Result<(), Error> {
    match SENT_MESSAGES.may_load(storage, key.clone())? {
        Some(_) => Err(Error::MessageAlreadyExists(key)),
        None => SENT_MESSAGES.save(storage, key, msg).map_err(Error::from),
    }
}

pub fn may_load_sent_msg(
    storage: &dyn Storage,
    id: &CrossChainId,
) -> Result<Option<Message>, Error> {
    SENT_MESSAGES
        .may_load(storage, id.clone())
        .map_err(Error::from)
}

pub fn may_load_received_msg(
    storage: &dyn Storage,
    cc_id: &CrossChainId,
) -> Result<Option<MessageWithStatus>, Error> {
    RECEIVED_MESSAGES
        .may_load(storage, cc_id.clone())
        .map_err(Error::from)
}

pub fn save_received_msg(
    storage: &mut dyn Storage,
    cc_id: CrossChainId,
    msg: Message,
) -> Result<(), Error> {
    let existing = RECEIVED_MESSAGES
        .may_load(storage, cc_id.clone())
        .map_err(Error::from)?;

    match existing {
        Some(MessageWithStatus {
            msg: existing_msg, ..
        }) if msg != existing_msg => Err(Error::MessageMismatch(msg.cc_id.clone())),
        Some(_) => Ok(()), // new message is identical, no need to store it
        None => RECEIVED_MESSAGES
            .save(
                storage,
                cc_id,
                &MessageWithStatus {
                    msg,
                    status: MessageStatus::Approved,
                },
            )
            .map_err(Error::from)?
            .then(Ok),
    }
}

/// Update the status of a message to executed if it is in approved status, error otherwise.
pub fn set_msg_as_executed(
    storage: &mut dyn Storage,
    cc_id: CrossChainId,
) -> Result<Message, Error> {
    let existing = RECEIVED_MESSAGES
        .may_load(storage, cc_id.clone())
        .map_err(Error::from)?;

    match existing {
        Some(MessageWithStatus {
            msg,
            status: MessageStatus::Approved,
        }) => {
            RECEIVED_MESSAGES
                .save(
                    storage,
                    cc_id,
                    &MessageWithStatus {
                        msg: msg.clone(),
                        status: MessageStatus::Executed,
                    },
                )
                .map_err(Error::from)?;

            Ok(msg)
        }
        Some(MessageWithStatus {
            status: MessageStatus::Executed,
            ..
        }) => Err(Error::MessageAlreadyExecuted(cc_id)),
        _ => Err(Error::MessageNotApproved(cc_id)),
    }
}

pub fn increment_msg_counter(storage: &mut dyn Storage) -> Result<u32, Error> {
    SENT_MESSAGE_COUNTER.incr(storage).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Addr;
    use router_api::{CrossChainId, Message};

    use super::*;

    fn create_test_message() -> Message {
        Message {
            cc_id: CrossChainId::new("source-chain", "message-id").unwrap(),
            source_address: "source-address".parse().unwrap(),
            destination_chain: "destination-chain".parse().unwrap(),
            destination_address: "destination-address".parse().unwrap(),
            payload_hash: [1; 32],
        }
    }

    #[test]
    fn config_storage() {
        let mut deps = mock_dependencies();

        let config = Config {
            chain_name: "test-chain".parse().unwrap(),
            router: Addr::unchecked("router-address"),
        };

        // Test saving config
        super::save_config(deps.as_mut().storage, &config).unwrap();

        // Test loading config
        let loaded_config = super::load_config(deps.as_ref().storage).unwrap();
        assert_eq!(config, loaded_config);

        // Test loading non-existent config
        CONFIG.remove(deps.as_mut().storage);
        let result = super::load_config(deps.as_ref().storage);
        assert_eq!(result, Err(Error::MissingConfig));
    }

    #[test]
    fn sent_message_storage() {
        let mut deps = mock_dependencies();
        let message = create_test_message();

        // Test saving sent message
        super::save_sent_msg(deps.as_mut().storage, message.cc_id.clone(), &message).unwrap();

        // Test loading sent message
        let loaded_message =
            super::may_load_sent_msg(deps.as_ref().storage, &message.cc_id).unwrap();
        assert_eq!(Some(message.clone()), loaded_message);

        // Test loading non-existent message
        let non_existent_id = CrossChainId::new("non-existent", "id").unwrap();
        assert_eq!(
            None,
            super::may_load_sent_msg(deps.as_ref().storage, &non_existent_id).unwrap()
        );

        // Test saving duplicate message
        let result = super::save_sent_msg(deps.as_mut().storage, message.cc_id.clone(), &message);
        assert_eq!(result, Err(Error::MessageAlreadyExists(message.cc_id)));
    }

    #[test]
    fn received_message_storage() {
        let mut deps = mock_dependencies();
        let message = create_test_message();

        // Test saving received message
        super::save_received_msg(
            deps.as_mut().storage,
            message.cc_id.clone(),
            message.clone(),
        )
        .unwrap();

        // Test loading received message
        let loaded_message =
            super::may_load_received_msg(deps.as_ref().storage, &message.cc_id).unwrap();
        assert_eq!(
            Some(MessageWithStatus {
                msg: message.clone(),
                status: MessageStatus::Approved
            }),
            loaded_message
        );

        // Test loading non-existent message
        let non_existent_id = CrossChainId::new("non-existent", "id").unwrap();
        assert_eq!(
            None,
            super::may_load_received_msg(deps.as_ref().storage, &non_existent_id).unwrap()
        );

        // Test saving duplicate message (should not error, but also not change the stored message)
        super::save_received_msg(
            deps.as_mut().storage,
            message.cc_id.clone(),
            message.clone(),
        )
        .unwrap();
        let loaded_message =
            super::may_load_received_msg(deps.as_ref().storage, &message.cc_id).unwrap();
        assert_eq!(
            Some(MessageWithStatus {
                msg: message.clone(),
                status: MessageStatus::Approved
            }),
            loaded_message
        );

        // Test saving mismatched message
        let mismatched_message = Message {
            cc_id: message.cc_id.clone(),
            source_address: "different-address".parse().unwrap(),
            ..message.clone()
        };
        let result = super::save_received_msg(
            deps.as_mut().storage,
            message.cc_id.clone(),
            mismatched_message,
        );
        assert_eq!(result, Err(Error::MessageMismatch(message.cc_id)));
    }

    #[test]
    fn set_msg_as_executed() {
        let mut deps = mock_dependencies();
        let message = create_test_message();

        // Save a received message
        super::save_received_msg(
            deps.as_mut().storage,
            message.cc_id.clone(),
            message.clone(),
        )
        .unwrap();

        // Test setting message as executed
        let executed_message =
            super::set_msg_as_executed(deps.as_mut().storage, message.cc_id.clone()).unwrap();
        assert_eq!(message, executed_message);

        // Verify the message status is now Executed
        let loaded_message =
            super::may_load_received_msg(deps.as_ref().storage, &message.cc_id).unwrap();
        assert_eq!(
            Some(MessageWithStatus {
                msg: message.clone(),
                status: MessageStatus::Executed
            }),
            loaded_message
        );

        // Test setting an already executed message
        let result = super::set_msg_as_executed(deps.as_mut().storage, message.cc_id.clone());
        assert_eq!(result, Err(Error::MessageAlreadyExecuted(message.cc_id)));

        // Test setting a non-existent message
        let non_existent_id = CrossChainId::new("non-existent", "id").unwrap();
        let result = super::set_msg_as_executed(deps.as_mut().storage, non_existent_id.clone());
        assert_eq!(result, Err(Error::MessageNotApproved(non_existent_id)));
    }

    #[test]
    fn increment_msg_counter() {
        let mut deps = mock_dependencies();

        for i in 1..=3 {
            let count = super::increment_msg_counter(deps.as_mut().storage).unwrap();
            assert_eq!(i, count);
        }
    }
}
