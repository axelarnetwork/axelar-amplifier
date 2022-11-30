use error_stack::{Report, Result};

use crate::report::Error;

pub mod config;
pub mod report;

pub fn run(_cfg: config::Config) -> Result<(), Error> {
    unimplemented!()
}
