use std::ops::Add;

use axelar_wasm_std::counter::Counter;
use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::IntoContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, Storage};
use cw_storage_plus::{Item, Map};
use error_stack::{report, Result, ResultExt};
use interchain_token_service_std::TokenId;
use router_api::{ChainName, ChainNameRaw, CrossChainId, Message};
use xrpl_types::types::{XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLToken};

#[cw_serde]
pub struct Config {
    pub verifier: Addr,
    pub router: Addr,
    pub its_hub: Addr,
    pub its_hub_chain_name: ChainName,
    pub chain_name: ChainName,
    pub xrpl_multisig: XRPLAccountId,
    pub xrp_token_id: TokenId,
}

const CONFIG: Item<Config> = Item::new("config");
const OUTGOING_MESSAGES: Map<&CrossChainId, Message> = Map::new("outgoing_messages");
const ROUTABLE_MESSAGES_INDEX: Counter<u32> = Counter::new("routable_message_index");

const XRPL_CURRENCY_TO_REMOTE_TOKEN_ID: Map<&XRPLCurrency, TokenId> =
    Map::new("xrpl_currency_to_remote_token_id");
const XRPL_TOKEN_TO_LOCAL_TOKEN_ID: Map<&XRPLToken, TokenId> =
    Map::new("xrpl_token_to_local_token_id");
const TOKEN_ID_TO_XRPL_TOKEN: Map<&TokenId, XRPLToken> = Map::new("token_id_to_xrpl_token");

#[allow(dead_code)]
#[deprecated(
    since = "1.3.2",
    note = "queried via interchain token service contract"
)]
const TOKEN_INSTACE_DECIMALS: Map<&(ChainNameRaw, TokenId), u8> =
    Map::new("token_instance_decimals");

const GAS_ACCRUED: Map<&TokenId, XRPLPaymentAmount> = Map::new("gas_accrued");
const GAS_COUNTED: Map<&Hash, ()> = Map::new("gas_counted");

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("message with ID {0} mismatches with the stored one")]
    MessageMismatch(CrossChainId),
    #[error("message with ID {0} not found")]
    MessageNotFound(CrossChainId),
    // This is a generic error to use when cw_storage_plus returns an error that is unexpected and
    // should never happen, such as an error encountered when saving data.
    #[error("storage error")]
    Storage,
    #[error("token with ID {0} not found")]
    TokenNotFound(TokenId),
    #[error("token ID for XRPL currency {0} not found")]
    TokenIdNotFound(XRPLCurrency),
    #[error("token ID for XRPL token {0} not found")]
    TokenIdNotFoundForToken(XRPLToken),
}

fn increment_gas(
    storage: &mut dyn Storage,
    token_id: &TokenId,
    new_gas: XRPLPaymentAmount,
) -> Result<XRPLPaymentAmount, Error> {
    GAS_ACCRUED
        .update(storage, token_id, |existing_gas| match existing_gas {
            Some(existing_gas) => existing_gas.add(new_gas),
            None => Ok(new_gas),
        })
        .change_context(Error::Storage)
}

fn gas_counted(storage: &dyn Storage, tx_hash: &HexTxHash) -> Result<bool, Error> {
    Ok(GAS_COUNTED
        .may_load(storage, &tx_hash.tx_hash)
        .change_context(Error::Storage)?
        .is_some())
}

fn mark_gas_counted(storage: &mut dyn Storage, tx_hash: &HexTxHash) -> Result<(), Error> {
    GAS_COUNTED
        .save(storage, &tx_hash.tx_hash, &())
        .change_context(Error::Storage)
}

pub fn count_gas(
    storage: &mut dyn Storage,
    tx_id: &HexTxHash,
    token_id: &TokenId,
    gas: XRPLPaymentAmount,
) -> Result<(), Error> {
    if gas.is_zero() || gas_counted(storage, tx_id)? {
        return Ok(());
    }

    increment_gas(storage, token_id, gas)?;
    mark_gas_counted(storage, tx_id)?;
    Ok(())
}

pub fn load_token_id(
    storage: &dyn Storage,
    xrpl_multisig: XRPLAccountId,
    token: &XRPLToken,
) -> Result<TokenId, Error> {
    let token_id = if token.is_remote(xrpl_multisig.clone()) {
        load_remote_token_id(storage, &token.currency)?
    } else {
        load_local_token_id(storage, token)?
    };

    Ok(token_id)
}

pub fn load_config(storage: &dyn Storage) -> Config {
    CONFIG.load(storage).expect("failed to load config")
}

pub fn save_config(storage: &mut dyn Storage, config: &Config) -> Result<(), Error> {
    CONFIG.save(storage, config).change_context(Error::Storage)
}

fn may_load_outgoing_message(
    storage: &dyn Storage,
    cc_id: &CrossChainId,
) -> Result<Option<Message>, Error> {
    OUTGOING_MESSAGES
        .may_load(storage, cc_id)
        .change_context(Error::Storage)
}

pub fn load_outgoing_message(
    storage: &dyn Storage,
    cc_id: &CrossChainId,
) -> Result<Message, Error> {
    may_load_outgoing_message(storage, cc_id)
        .change_context(Error::Storage)?
        .ok_or_else(|| report!(Error::MessageNotFound(cc_id.to_owned())))
}

pub fn save_outgoing_message(
    storage: &mut dyn Storage,
    cc_id: &CrossChainId,
    msg: &Message,
) -> Result<(), Error> {
    match may_load_outgoing_message(storage, cc_id).change_context(Error::Storage)? {
        Some(existing) if msg.hash() != existing.hash() => {
            Err(report!(Error::MessageMismatch(msg.cc_id.clone())))
        }
        Some(_) => Ok(()), // new message is identical, no need to store it
        None => Ok(OUTGOING_MESSAGES
            .save(storage, cc_id, msg)
            .change_context(Error::Storage)?),
    }
}

pub fn may_load_xrpl_token(
    storage: &dyn Storage,
    token_id: &TokenId,
) -> Result<Option<XRPLToken>, Error> {
    TOKEN_ID_TO_XRPL_TOKEN
        .may_load(storage, token_id)
        .change_context(Error::Storage)
}

pub fn load_xrpl_token(storage: &dyn Storage, token_id: &TokenId) -> Result<XRPLToken, Error> {
    may_load_xrpl_token(storage, token_id)
        .change_context(Error::Storage)?
        .ok_or_else(|| report!(Error::TokenNotFound(token_id.to_owned())))
}

pub fn may_load_local_token_id(
    storage: &dyn Storage,
    xrpl_token: &XRPLToken,
) -> Result<Option<TokenId>, Error> {
    XRPL_TOKEN_TO_LOCAL_TOKEN_ID
        .may_load(storage, xrpl_token)
        .change_context(Error::Storage)
}

pub fn load_local_token_id(
    storage: &dyn Storage,
    xrpl_token: &XRPLToken,
) -> Result<TokenId, Error> {
    may_load_local_token_id(storage, xrpl_token)
        .change_context(Error::Storage)?
        .ok_or_else(|| report!(Error::TokenIdNotFoundForToken(xrpl_token.to_owned())))
}

pub fn save_local_token_id(
    storage: &mut dyn Storage,
    xrpl_token: &XRPLToken,
    token_id: &TokenId,
) -> Result<(), Error> {
    XRPL_TOKEN_TO_LOCAL_TOKEN_ID
        .save(storage, xrpl_token, token_id)
        .change_context(Error::Storage)
}

pub fn save_xrpl_token(
    storage: &mut dyn Storage,
    token_id: &TokenId,
    xrpl_token: &XRPLToken,
) -> Result<(), Error> {
    TOKEN_ID_TO_XRPL_TOKEN
        .save(storage, token_id, xrpl_token)
        .change_context(Error::Storage)
}

pub fn increment_event_index(storage: &mut dyn Storage) -> Result<u32, Error> {
    ROUTABLE_MESSAGES_INDEX
        .incr(storage)
        .change_context(Error::Storage)
}

pub fn may_load_remote_token_id(
    storage: &dyn Storage,
    xrpl_currency: &XRPLCurrency,
) -> Result<Option<TokenId>, Error> {
    XRPL_CURRENCY_TO_REMOTE_TOKEN_ID
        .may_load(storage, xrpl_currency)
        .change_context(Error::Storage)
}

pub fn load_remote_token_id(
    storage: &dyn Storage,
    xrpl_currency: &XRPLCurrency,
) -> Result<TokenId, Error> {
    may_load_remote_token_id(storage, xrpl_currency)
        .change_context(Error::Storage)?
        .ok_or_else(|| report!(Error::TokenIdNotFound(xrpl_currency.to_owned())))
}

pub fn save_remote_token_id(
    storage: &mut dyn Storage,
    xrpl_currency: &XRPLCurrency,
    token_id: &TokenId,
) -> Result<(), Error> {
    XRPL_CURRENCY_TO_REMOTE_TOKEN_ID
        .save(storage, xrpl_currency, token_id)
        .change_context(Error::Storage)
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::msg_id::HexTxHash;
    use cosmwasm_std::testing::mock_dependencies;
    use interchain_token_service_std::TokenId;
    use router_api::{CrossChainId, Message};
    use xrpl_types::types::{XRPLPaymentAmount, XRPLToken, XRPLTokenAmount};

    use crate::state::{count_gas, Error, GAS_ACCRUED, GAS_COUNTED, OUTGOING_MESSAGES};

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

    #[test]
    fn count_gas_accumulates_per_token_and_counts_each_transaction_once() {
        let mut deps = mock_dependencies();
        let token_id = TokenId::new([1; 32]);
        let first_tx = HexTxHash::new([1; 32]);
        let second_tx = HexTxHash::new([2; 32]);

        count_gas(
            deps.as_mut().storage,
            &first_tx,
            &token_id,
            XRPLPaymentAmount::Drops(100),
        )
        .unwrap();
        count_gas(
            deps.as_mut().storage,
            &second_tx,
            &token_id,
            XRPLPaymentAmount::Drops(50),
        )
        .unwrap();
        // replaying a transaction must not count its gas again
        count_gas(
            deps.as_mut().storage,
            &first_tx,
            &token_id,
            XRPLPaymentAmount::Drops(100),
        )
        .unwrap();

        assert_eq!(
            GAS_ACCRUED.load(&deps.storage, &token_id).unwrap(),
            XRPLPaymentAmount::Drops(150)
        );
    }

    #[test]
    fn count_gas_ignores_zero_amounts() {
        let mut deps = mock_dependencies();
        let token_id = TokenId::new([1; 32]);
        let tx = HexTxHash::new([1; 32]);

        count_gas(
            deps.as_mut().storage,
            &tx,
            &token_id,
            XRPLPaymentAmount::Drops(0),
        )
        .unwrap();

        assert_eq!(
            GAS_ACCRUED.may_load(&deps.storage, &token_id).unwrap(),
            None
        );
        // the transaction is not marked, so a later top-up for it is still counted
        assert_eq!(
            GAS_COUNTED.may_load(&deps.storage, &tx.tx_hash).unwrap(),
            None
        );
    }

    #[test]
    fn count_gas_rejects_amount_in_another_token() {
        let mut deps = mock_dependencies();
        let token_id = TokenId::new([1; 32]);
        let token = XRPLToken {
            issuer: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".parse().unwrap(),
            currency: "USD".to_string().try_into().unwrap(),
        };
        count_gas(
            deps.as_mut().storage,
            &HexTxHash::new([1; 32]),
            &token_id,
            XRPLPaymentAmount::Drops(100),
        )
        .unwrap();

        let err = count_gas(
            deps.as_mut().storage,
            &HexTxHash::new([2; 32]),
            &token_id,
            XRPLPaymentAmount::Issued(token, XRPLTokenAmount::new(1_000_000_000_000_000, -15)),
        )
        .unwrap_err();

        assert!(matches!(err.current_context(), Error::Storage));
        assert_eq!(
            GAS_ACCRUED.load(&deps.storage, &token_id).unwrap(),
            XRPLPaymentAmount::Drops(100)
        );
    }
}
