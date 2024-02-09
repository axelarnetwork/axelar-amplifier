use std::convert::TryFrom;
use std::convert::TryInto;
use std::path::Path;

use cosmrs::{cosmwasm::MsgExecuteContract, tx::Msg};
use error_stack::{Result, ResultExt};
use multisig::{
    key::{KeyType, PublicKey},
    msg::ExecuteMsg,
};
use report::ResultCompatExt;
use sha3::{Digest, Keccak256};
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

    let ecdsa_client = SharableEcdsaClient::new(
        MultisigClient::connect(tofnd_config.party_uid, tofnd_config.url)
            .await
            .change_context(Error::Connection)?,
    );
    let multisig_key = ecdsa_client
        .keygen(&multisig_address.to_string())
        .await
        .change_context(Error::Tofnd)?;
    info!(key_id = multisig_address.to_string(), "keygen successful");

    let sender = pub_key.account_id(PREFIX).change_context(Error::Tofnd)?;

    let address_hash: [u8; 32] = Keccak256::digest(sender.as_ref().as_bytes())
        .as_slice()
        .try_into()
        .expect("wrong length");

    let signed_sender_address = ecdsa_client
        .sign(
            &multisig_address.to_string(),
            address_hash.into(),
            &multisig_key,
        )
        .await
        .change_context(Error::Tofnd)?
        .into();

    let msg = serde_json::to_vec(&ExecuteMsg::RegisterPublicKey {
        public_key: PublicKey::try_from((KeyType::Ecdsa, multisig_key.to_bytes().into()))
            .change_context(Error::Tofnd)?,
        signed_sender_address,
    })
    .expect("register public key msg should serialize");

    let tx = MsgExecuteContract {
        sender,
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
            if let handlers::config::Config::MultisigSigner { cosmwasm_contract, message_provider } = config {
                Some(cosmwasm_contract.clone())
            } else {
                None
            }
        })
        .ok_or(Error::LoadConfig)
        .attach_printable("no multisig contract found in config")
}
