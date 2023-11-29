use std::path::Path;

use error_stack::Result;

use crate::commands::worker_pub_key;
use crate::tofnd::Config;
use crate::Error;
use crate::PREFIX;

pub async fn run(config: Config, state_path: &Path) -> Result<(), Error> {
    worker_pub_key(state_path, config).await.map(|pub_key| {
        println!(
            "worker address: {}",
            pub_key
                .account_id(PREFIX)
                .expect("failed to convert to account identifier")
        )
    })
}
