use cosmwasm_std::{Coin, MessageInfo};
use error_stack::{bail, Result};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid token: one and only one token is required for this operation, got {0:?}")]
    MultipleTokens(Vec<Coin>),
}

pub trait GetToken {
    fn token(&self) -> Result<Option<Coin>, Error>;
}

impl GetToken for MessageInfo {
    fn token(&self) -> Result<Option<Coin>, Error> {
        match self.funds.as_slice() {
            [] => Ok(None),
            [token] => Ok(Some(token.clone())),
            _ => bail!(Error::MultipleTokens(self.funds.clone())),
        }
    }
}
