use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    SnarkVm(#[from] snarkvm_cosmwasm::prelude::Error),
}
