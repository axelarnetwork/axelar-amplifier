use thiserror::Error;

#[derive(Error, Debug)]
pub enum AleoError {
    #[error(transparent)]
    SnarkVm(#[from] snarkvm_cosmwasm::prelude::Error),
}
