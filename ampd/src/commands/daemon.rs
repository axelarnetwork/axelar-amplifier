use error_stack::Report;

use crate::config::Config;
use crate::Error;

pub async fn run(config: Config) -> Result<Option<String>, Report<Error>> {
    crate::run(config).await.map(|_| None)
}
