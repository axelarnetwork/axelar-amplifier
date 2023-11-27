use error_stack::{Report, ResultExt};
use std::path::PathBuf;

use crate::state::{load, StateUpdater};
use crate::tofnd::grpc::{MultisigClient, SharableEcdsaClient};
use crate::tofnd::Config;
use crate::Error;
use crate::PREFIX;

pub async fn run(config: Config, state_path: PathBuf) -> Result<(), Report<Error>> {
    let state = load(&state_path).change_context(Error::LoadConfig)?;
    let mut state_updater = StateUpdater::new(state);
    match state_updater.state().pub_key {
        Some(pub_key) => Ok(pub_key),
        None => {
            let pub_key = SharableEcdsaClient::new(
                MultisigClient::connect(config.party_uid, config.url)
                    .await
                    .change_context(Error::Connection)?,
            )
            .keygen(&config.key_uid)
            .await
            .change_context(Error::Tofnd)?;

            state_updater.as_mut().pub_key = Some(pub_key);

            Ok(pub_key)
        }
    }
    .map(|pub_key| {
        println!(
            "worker address: {}",
            pub_key
                .account_id(PREFIX)
                .expect("failed to convert to account identifier")
                .to_string()
        )
    })
}
