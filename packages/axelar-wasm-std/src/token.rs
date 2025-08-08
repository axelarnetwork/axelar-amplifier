use cosmwasm_std::{Coin, MessageInfo};
use error_stack::{ensure, Result};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid token: one and only one token is required for this operation, got {0:?}")]
    MultipleTokens(Vec<Coin>),
}

pub trait GetToken {
    fn single_token(&self) -> Result<Option<Coin>, Error>;
}

impl GetToken for MessageInfo {
    fn single_token(&self) -> Result<Option<Coin>, Error> {
        ensure!(
            self.funds.len() <= 1,
            Error::MultipleTokens(self.funds.clone())
        );

        Ok(self.funds.first().cloned())
    }
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use cosmwasm_std::{coin, coins};
    use router_api::cosmos_addr;

    use super::*;
    use crate::assert_err_contains;

    #[test]
    fn single_token() {
        let message_info = MessageInfo {
            sender: cosmos_addr!("sender"),
            funds: coins(100, "token"),
        };

        let result = assert_ok!(message_info.single_token());
        assert_eq!(result, Some(coin(100, "token")));
    }

    #[test]
    fn no_token() {
        let message_info = MessageInfo {
            sender: cosmos_addr!("sender"),
            funds: vec![],
        };

        let result = assert_ok!(message_info.single_token());
        assert_eq!(result, None);
    }

    #[test]
    fn multiple_tokens() {
        let message_info = MessageInfo {
            sender: cosmos_addr!("sender"),
            funds: vec![coin(100, "token1"), coin(200, "token2")],
        };

        assert_err_contains!(message_info.single_token(), Error, Error::MultipleTokens(_));
    }
}
