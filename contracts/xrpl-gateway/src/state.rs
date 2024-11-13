use axelar_wasm_std::{counter::Counter, IntoContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, Storage};
use cw_storage_plus::{Item, Map};
use interchain_token_service::TokenId;
use router_api::{ChainName, CrossChainId, Message};
use xrpl_types::types::{XRPLAccountId, XRPLCurrency, XRPLRemoteInterchainTokenInfo};

#[cw_serde]
pub struct Config {
    pub verifier: Addr,
    pub router: Addr,
    pub its_hub: Addr,
    pub axelar_chain_name: ChainName,
    pub xrpl_chain_name: ChainName,
    pub xrpl_multisig: XRPLAccountId,
}

const CONFIG: Item<Config> = Item::new("config");
const OUTGOING_MESSAGES: Map<&CrossChainId, Message> = Map::new("outgoing_messages");

const XRPL_CURRENCY_TO_TOKEN_ID: Map<[u8; 20], TokenId> = Map::new("xrpl_currency_to_token_id"); // TODO: rename to indicate that this is only relevant for remote tokens
const TOKEN_ID_TO_TOKEN_INFO: Map<&TokenId, XRPLRemoteInterchainTokenInfo> = Map::new("token_id_to_token_info");
const ROUTABLE_MESSAGES_INDEX: Counter<u32> = Counter::new("routable_message_index");

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
    #[error("token with ID {0} not found")]
    TokenNotFound(TokenId),
    #[error("token ID for XRPL currency {0} not found")]
    TokenIdNotFound(XRPLCurrency),
}

pub fn load_config(storage: &dyn Storage) -> Result<Config, Error> {
    CONFIG
        .may_load(storage)
        .map_err(Error::from)?
        .ok_or(Error::MissingConfig)
}

pub fn save_config(storage: &mut dyn Storage, config: &Config) -> Result<(), Error> {
    CONFIG.save(storage, config).map_err(Error::from)
}

pub fn load_outgoing_message(
    storage: &dyn Storage,
    cc_id: &CrossChainId,
) -> Result<Message, Error> {
    OUTGOING_MESSAGES
        .may_load(storage, cc_id)
        .map_err(Error::from)?
        .ok_or_else(|| Error::MessageNotFound(cc_id.clone()))
}

pub fn save_outgoing_message(
    storage: &mut dyn Storage,
    cc_id: &CrossChainId,
    msg: &Message,
) -> Result<(), Error> {
    let existing = OUTGOING_MESSAGES
        .may_load(storage, cc_id)
        .map_err(Error::from)?;

    match existing {
        Some(existing) if msg.hash() != existing.hash() => {
            Err(Error::MessageMismatch(msg.cc_id.clone()))
        }
        Some(_) => Ok(()), // new message is identical, no need to store it
        None => Ok(OUTGOING_MESSAGES
            .save(storage, cc_id, msg)
            .map_err(Error::from)?),
    }
}

pub fn load_token_info(
    storage: &dyn Storage,
    token_id: &TokenId,
) -> Result<XRPLRemoteInterchainTokenInfo, Error> {
    TOKEN_ID_TO_TOKEN_INFO
        .may_load(storage, token_id)
        .map_err(Error::from)?
        .ok_or_else(|| Error::TokenNotFound(token_id.clone()))
}

pub fn save_token_info(
    storage: &mut dyn Storage,
    token_id: &TokenId,
    token_info: &XRPLRemoteInterchainTokenInfo,
) -> Result<(), Error> {
    TOKEN_ID_TO_TOKEN_INFO
        .save(storage, token_id, token_info)
        .map_err(Error::from)
}

pub fn increment_event_index(storage: &mut dyn Storage) -> Result<u32, Error> {
    ROUTABLE_MESSAGES_INDEX
        .incr(storage)
        .map_err(Error::from)
}

pub fn load_token_id(
    storage: &dyn Storage,
    xrpl_currency: XRPLCurrency,
) -> Result<TokenId, Error> {
    XRPL_CURRENCY_TO_TOKEN_ID
        .may_load(storage, xrpl_currency.clone().into())
        .map_err(Error::from)?
        .ok_or_else(|| Error::TokenIdNotFound(xrpl_currency))
}

pub fn save_xrpl_currency_token_id(
    storage: &mut dyn Storage,
    xrpl_currency: XRPLCurrency,
    token_id: &TokenId
) -> Result<(), Error> {
    XRPL_CURRENCY_TO_TOKEN_ID
        .save(storage, xrpl_currency.into(), token_id)
        .map_err(Error::from)
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::mock_dependencies;
    use router_api::{CrossChainId, Message};

    use crate::state::OUTGOING_MESSAGES;

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
