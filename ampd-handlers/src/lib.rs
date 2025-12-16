pub mod evm;
pub mod multisig;
pub mod stellar;
pub mod tracing;
pub mod voting;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

use std::path::PathBuf;

use clap::{command, Parser};

#[derive(Parser)]
#[command(version)]
pub struct Args {
    /// Set the directory for config files lookup. Defaults to the current directory.
    #[arg(short, long, default_value = ".")]
    pub config_dir: PathBuf,
}
