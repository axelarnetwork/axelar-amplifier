use error_stack::Result;

use crate::report::Error;

mod broadcaster;
pub mod config;
pub mod deserializers;
pub mod event_processor;
pub mod event_sub;
pub mod handlers;
pub mod json_rpc;
pub mod report;
pub mod tm_client;
pub mod types;
mod url;

pub fn run(_cfg: config::Config) -> Result<(), Error> {
    unimplemented!()
}
