use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid starknet address")]
    InvalidAddress,
}
