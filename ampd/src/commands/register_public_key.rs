use std::convert::TryFrom;
use std::path::Path;

use cosmrs::{cosmwasm::MsgExecuteContract, tx::Msg};
use error_stack::{Result, ResultExt};
use multisig::{
    key::{KeyType, PublicKey},
    msg::ExecuteMsg,
};
use report::ResultCompatExt;
use tracing::info;

use crate::commands::{broadcast_tx, worker_pub_key};
use crate::config::Config;
use crate::tofnd::grpc::{MultisigClient, SharableEcdsaClient};
use crate::types::TMAddress;
use crate::{handlers, Error, PREFIX};

pub async fn run(config: Config, state_path: &Path) -> Result<Option<String>, Error> {
    let pub_key = worker_pub_key(state_path, config.tofnd_config.clone()).await?;

    let multisig_address = get_multisig_address(&config)?;

    let tofnd_config = config.tofnd_config.clone();
    let multisig_key = SharableEcdsaClient::new(
        MultisigClient::connect(tofnd_config.party_uid, tofnd_config.url)
            .await
            .change_context(Error::Connection)?,
    )
    .keygen(&multisig_address.to_string())
    .await
    .change_context(Error::Tofnd)?;
    info!(key_id = multisig_address.to_string(), "keygen successful");

    let msg = serde_json::to_vec(&ExecuteMsg::RegisterPublicKey {
        public_key: PublicKey::try_from((KeyType::Ecdsa, multisig_key.to_bytes().into()))
            .change_context(Error::Tofnd)?,
    })
    .expect("register public key msg should serialize");

    let tx = MsgExecuteContract {
        sender: pub_key.account_id(PREFIX).change_context(Error::Tofnd)?,
        contract: multisig_address.as_ref().clone(),
        msg,
        funds: vec![],
    }
    .into_any()
    .expect("failed to serialize proto message");

    let tx_hash = broadcast_tx(config, tx, pub_key).await?.txhash;

    Ok(Some(format!(
        "successfully broadcast register public key transaction, tx hash: {}",
        tx_hash
    )))
}

fn get_multisig_address(config: &Config) -> Result<TMAddress, Error> {
    config
        .handlers
        .iter()
        .find_map(|config| {
            if let handlers::config::Config::MultisigSigner { cosmwasm_contract } = config {
                Some(cosmwasm_contract.clone())
            } else {
                None
            }
        })
        .ok_or(Error::LoadConfig)
        .attach_printable("no multisig contract found in config")
}
