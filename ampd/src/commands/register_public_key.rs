use std::convert::TryFrom;
use std::path::Path;

use cosmrs::{cosmwasm::MsgExecuteContract, tx::Msg};
use error_stack::{Result, ResultExt};
use multisig::{
    key::{KeyType, PublicKey},
    msg::ExecuteMsg,
};
use report::ResultCompatExt;

use crate::commands::{broadcast_tx, worker_pub_key};
use crate::config::Config;
use crate::{handlers, Error, PREFIX};

pub async fn run(config: Config, state_path: &Path) -> Result<Option<String>, Error> {
    let pub_key = worker_pub_key(state_path, config.tofnd_config.clone()).await?;

    let multisig_address = config
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
        .attach_printable("no multisig contract found in config")?;

    let msg = serde_json::to_vec(&ExecuteMsg::RegisterPublicKey {
        public_key: PublicKey::try_from((KeyType::Ecdsa, pub_key.to_bytes().into()))
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

    Ok(Some(format!(
        "successfully broadcast register public key transaction, tx hash: {}",
        broadcast_tx(config, tx, pub_key).await?.txhash
    )))
}
