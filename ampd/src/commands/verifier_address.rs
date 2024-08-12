use axelar_wasm_std::FnExt;
use error_stack::Result;
use report::ResultCompatExt;

use crate::commands::verifier_pub_key;
use crate::tofnd::Config as TofndConfig;
use crate::{Error, PREFIX};

pub async fn run(config: TofndConfig) -> Result<Option<String>, Error> {
    verifier_pub_key(config)
        .await
        .and_then(|pub_key| pub_key.account_id(PREFIX).change_context(Error::Tofnd))?
        .then(|account_id| Ok(Some(format!("verifier address: {}", account_id))))
}
