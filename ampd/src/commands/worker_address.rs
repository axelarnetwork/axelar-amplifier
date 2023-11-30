use std::fmt::Display;
use std::path::Path;

use axelar_wasm_std::FnExt;
use error_stack::Result;
use report::ResultCompatExt;

use crate::commands::worker_pub_key;
use crate::tofnd::Config as TofndConfig;
use crate::Error;
use crate::PREFIX;

pub async fn run(config: TofndConfig, state_path: &Path) -> Result<Box<dyn Display>, Error> {
    worker_pub_key(state_path, config)
        .await
        .and_then(|pub_key| pub_key.account_id(PREFIX).change_context(Error::Tofnd))?
        .then(|account_id| {
            Ok(Box::new(format!("worker address: {}", account_id)) as Box<dyn Display>)
        })
}
