use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::{Item, Map};
use error_stack::{Result, ResultExt};
use router_api::{CrossChainId, Message};

#[cw_serde]
pub(crate) struct Config {
    pub verifier: Addr,
    pub router: Addr,
}

pub(crate) fn save_config(storage: &mut dyn Storage, value: &Config) -> Result<(), Error> {
    CONFIG
        .save(storage, value)
        .change_context(Error::SaveValue(CONFIG_NAME))
}
pub(crate) fn load_config(storage: &dyn Storage) -> Result<Config, Error> {
    CONFIG
        .load(storage)
        .change_context(Error::LoadValue(CONFIG_NAME))
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("failed to save {0}")]
    SaveValue(&'static str),
    #[error("failed to load {0}")]
    LoadValue(&'static str),
}

const CONFIG_NAME: &str = "config";
const CONFIG: Item<Config> = Item::new(CONFIG_NAME);
const OUTGOING_MESSAGES_NAME: &str = "outgoing_messages";
pub const OUTGOING_MESSAGES: Map<&CrossChainId, Message> = Map::new(OUTGOING_MESSAGES_NAME);

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Addr;
    use router_api::{CrossChainId, Message};

    use crate::state::{load_config, save_config, Config, OUTGOING_MESSAGES};

    #[test]
    fn config_storage() {
        let mut deps = mock_dependencies();

        let config = Config {
            verifier: Addr::unchecked("verifier"),
            router: Addr::unchecked("router"),
        };
        assert!(save_config(deps.as_mut().storage, &config).is_ok());

        assert_eq!(load_config(&deps.storage).unwrap(), config);
    }

    #[test]
    fn outgoing_messages_storage() {
        let mut deps = mock_dependencies();

        let message = Message {
            cc_id: CrossChainId::new("chain", "id").unwrap(),
            source_address: "source-address".parse().unwrap(),
            destination_chain: "destination".parse().unwrap(),
            destination_address: "destination-address".parse().unwrap(),
            payload_hash: [1; 32],
        };

        assert!(OUTGOING_MESSAGES
            .save(deps.as_mut().storage, &message.cc_id, &message)
            .is_ok());

        assert_eq!(
            OUTGOING_MESSAGES
                .may_load(&deps.storage, &message.cc_id)
                .unwrap(),
            Some(message)
        );

        let unknown_chain_id = CrossChainId::new("unknown", "id").unwrap();

        assert_eq!(
            OUTGOING_MESSAGES
                .may_load(&deps.storage, &unknown_chain_id)
                .unwrap(),
            None
        );

        let unknown_id = CrossChainId::new("chain", "unkown").unwrap();
        assert_eq!(
            OUTGOING_MESSAGES
                .may_load(&deps.storage, &unknown_id)
                .unwrap(),
            None
        );
    }
}
