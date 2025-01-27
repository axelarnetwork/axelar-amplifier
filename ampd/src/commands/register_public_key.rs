use std::convert::{TryFrom, TryInto};

use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use error_stack::{Result, ResultExt};
use multisig::key::PublicKey;
use multisig::msg::ExecuteMsg;
use report::ResultCompatExt;
use sha3::{Digest, Keccak256};
use tracing::info;
use valuable::Valuable;

use crate::commands::{broadcast_tx, verifier_pub_key};
use crate::config::Config;
use crate::tofnd::grpc::{Multisig, MultisigClient};
use crate::tofnd::{self};
use crate::types::TMAddress;
use crate::{handlers, Error, PREFIX};

#[derive(clap::ValueEnum, Clone, Debug, Valuable, Copy)]
enum KeyType {
    Ecdsa,
    Ed25519,
}

impl From<KeyType> for tofnd::Algorithm {
    fn from(val: KeyType) -> Self {
        match val {
            KeyType::Ecdsa => tofnd::Algorithm::Ecdsa,
            KeyType::Ed25519 => tofnd::Algorithm::Ed25519,
        }
    }
}

impl From<KeyType> for multisig::key::KeyType {
    fn from(val: KeyType) -> Self {
        match val {
            KeyType::Ecdsa => multisig::key::KeyType::Ecdsa,
            KeyType::Ed25519 => multisig::key::KeyType::Ed25519,
        }
    }
}

#[derive(clap::Args, Debug, Valuable)]
pub struct Args {
    key_type: KeyType,
}

pub async fn run(config: Config, args: Args) -> Result<Option<String>, Error> {
    let pub_key = verifier_pub_key(config.tofnd_config.clone()).await?;

    let multisig_address = multisig_address(&config)?;

    let tofnd_config = config.tofnd_config.clone();

    let multisig_client = MultisigClient::new(tofnd_config.party_uid, tofnd_config.url.clone())
        .await
        .change_context(Error::Connection)
        .attach_printable(tofnd_config.url)?;
    let multisig_key = multisig_client
        .keygen(&multisig_address.to_string(), args.key_type.into())
        .await
        .change_context(Error::Tofnd)?;

    info!(key_id = multisig_address.to_string(), "keygen successful");

    let sender = pub_key.account_id(PREFIX).change_context(Error::Tofnd)?;

    let address_hash: [u8; 32] = Keccak256::digest(sender.as_ref().as_bytes())
        .as_slice()
        .try_into()
        .expect("wrong length");

    let signed_sender_address = multisig_client
        .sign(
            &multisig_address.to_string(),
            address_hash.into(),
            &multisig_key,
            args.key_type.into(),
        )
        .await
        .change_context(Error::Tofnd)?
        .into();

    let msg = serde_json::to_vec(&ExecuteMsg::RegisterPublicKey {
        public_key: PublicKey::try_from((args.key_type.into(), multisig_key.to_bytes().into()))
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

fn multisig_address(config: &Config) -> Result<TMAddress, Error> {
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
