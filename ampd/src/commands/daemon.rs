use std::path::Path;

use error_stack::{Report, ResultExt};
use tracing::info;

use crate::config::Config;
use crate::state::{flush, load};
use crate::Error;

pub async fn run(config: Config, state_path: &Path) -> Result<Option<String>, Report<Error>> {
    let state = load(state_path).change_context(Error::LoadConfig)?;
    let (state, execution_result) = crate::run(config, state).await;

    info!("persisting state");
    let state_flush_result = flush(&state, state_path).change_context(Error::ReturnState);

    match (execution_result, state_flush_result) {
        // both execution and persisting state failed: return the merged error
        (Err(mut report), Err(state_err)) => {
            report.extend_one(state_err);
            Err(report)
        }

        // any single path failed: report the error
        (Err(report), Ok(())) | (Ok(()), Err(report)) => Err(report),

        // no errors in either execution or persisting state
        (Ok(()), Ok(())) => Ok(None),
    }
}
