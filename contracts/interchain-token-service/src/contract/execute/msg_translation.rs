use cosmwasm_std::{HexBinary, QuerierWrapper, Storage};
use error_stack::{Result, ResultExt};
use interchain_token_service_std::HubMessage;
use its_msg_translator_api::Client as TranslationClient;
use router_api::ChainNameRaw;

use super::Error;
use crate::state;

/// Translate chain-specific payload to standardized ITS Hub Message format using translation contract
pub fn translate_from_bytes(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    source_chain: &ChainNameRaw,
    payload: &HexBinary,
) -> Result<HubMessage, Error> {
    let chain_config =
        state::load_chain_config(storage, source_chain).change_context(Error::State)?;

    let translation_client: TranslationClient =
        client::ContractClient::new(querier, &chain_config.msg_translator).into();

    translation_client
        .from_bytes(payload.clone())
        .change_context(Error::InvalidPayload)
}

/// Translate standardized ITS Hub Message to chain-specific payload format using translation contract
pub fn translate_to_bytes(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: &ChainNameRaw,
    hub_message: &HubMessage,
) -> Result<HexBinary, Error> {
    let chain_config =
        state::load_chain_config(storage, destination_chain).change_context(Error::State)?;

    let translation_client: TranslationClient =
        client::ContractClient::new(querier, &chain_config.msg_translator).into();

    translation_client
        .to_bytes(hub_message.clone())
        .change_context(Error::TranslationFailed)
} 