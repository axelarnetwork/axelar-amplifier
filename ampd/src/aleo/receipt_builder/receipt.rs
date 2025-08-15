use error_stack::Report;
use snarkvm::prelude::Network;

use crate::aleo::error::Error;

#[derive(Debug)]
pub enum Receipt<N: Network, T> {
    Found(T),
    NotFound(N::TransitionID, Report<Error>),
}
