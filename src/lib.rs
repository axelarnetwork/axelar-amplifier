use error_stack::Result;

use crate::report::Error;

pub mod config;
pub mod event_sub;
pub mod report;

pub fn run(_cfg: config::Config) -> Result<(), Error> {
    unimplemented!()
}
