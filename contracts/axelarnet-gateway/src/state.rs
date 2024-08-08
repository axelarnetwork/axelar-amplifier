use axelar_wasm_std::counter::Counter;
use axelar_wasm_std::{FnExt, IntoContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, Storage};
use cw_storage_plus::{Item, Map};
use router_api::{ChainName, CrossChainId, Message};

#[cw_serde]
pub(crate) struct Config {
    pub chain_name: ChainName,
    pub router: Addr,
}

#[cw_serde]
pub(crate) enum MessageStatus {
    Approved,
    Executed,
}

#[cw_serde]
pub(crate) struct MessageWithStatus {
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

#[derive(thiserror::Error, Debug, IntoContractError)]
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

pub(crate) fn save_config(storage: &mut dyn Storage, value: &Config) -> Result<(), Error> {
    CONFIG.save(storage, value).map_err(Error::from)
}

pub(crate) fn load_config(storage: &dyn Storage) -> Result<Config, Error> {
    CONFIG
        .may_load(storage)
        .map_err(Error::from)?
        .ok_or(Error::MissingConfig)
}

pub(crate) fn save_sent_msg(
    storage: &mut dyn Storage,
    key: CrossChainId,
    msg: &Message,
) -> Result<(), Error> {
    match SENT_MESSAGES.may_load(storage, key.clone())? {
        Some(_) => Err(Error::MessageAlreadyExists(key)),
        None => SENT_MESSAGES.save(storage, key, msg).map_err(Error::from),
    }
}

pub(crate) fn may_load_sent_msg(
    storage: &dyn Storage,
    id: &CrossChainId,
) -> Result<Option<Message>, Error> {
    SENT_MESSAGES
        .may_load(storage, id.clone())
        .map_err(Error::from)
}

#[cfg(test)]
pub(crate) fn may_load_received_msg(
    storage: &dyn Storage,
    cc_id: &CrossChainId,
) -> Result<Option<MessageWithStatus>, Error> {
    RECEIVED_MESSAGES
        .may_load(storage, cc_id.clone())
        .map_err(Error::from)
}

pub(crate) fn save_received_msg(
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
pub(crate) fn set_msg_as_executed(
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

pub(crate) fn increment_msg_counter(storage: &mut dyn Storage) -> Result<u32, Error> {
    SENT_MESSAGE_COUNTER.incr(storage).map_err(Error::from)
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Addr;
    use router_api::{CrossChainId, Message};

    use crate::state::{
        load_config, may_load_received_msg, save_config, save_received_msg, Config,
        MessageWithStatus,
    };

    #[test]
    fn config_storage() {
        let mut deps = mock_dependencies();

        let config = Config {
            chain_name: "chain".parse().unwrap(),
            router: Addr::unchecked("router"),
        };
        assert!(save_config(deps.as_mut().storage, &config).is_ok());

        assert_eq!(load_config(&deps.storage).unwrap(), config);
    }

    #[test]
    fn outgoing_messages_storage() {
        let mut deps = mock_dependencies();

        let msg = Message {
            cc_id: CrossChainId {
                source_chain: "chain".parse().unwrap(),
                message_id: "id".parse().unwrap(),
            },
            source_address: "source-address".parse().unwrap(),
            destination_chain: "destination".parse().unwrap(),
            destination_address: "destination-address".parse().unwrap(),
            payload_hash: [1; 32],
        };
        let msg_with_status = MessageWithStatus {
            msg: msg.clone(),
            status: crate::state::MessageStatus::Approved,
        };

        assert!(save_received_msg(deps.as_mut().storage, msg.cc_id.clone(), msg.clone(),).is_ok());

        assert_eq!(
            may_load_received_msg(&deps.storage, &msg.cc_id).unwrap(),
            Some(msg_with_status)
        );

        let unknown_chain_id = CrossChainId {
            source_chain: "unknown".parse().unwrap(),
            message_id: "id".parse().unwrap(),
        };

        assert_eq!(
            may_load_received_msg(&deps.storage, &unknown_chain_id).unwrap(),
            None
        );

        let unknown_id = CrossChainId {
            source_chain: "chain".parse().unwrap(),
            message_id: "unknown".parse().unwrap(),
        };
        assert_eq!(
            may_load_received_msg(&deps.storage, &unknown_id).unwrap(),
            None
        );
    }
}
