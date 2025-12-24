use axelar_wasm_std::voting::WeightedPoll;
use cosmwasm_schema::cw_serde;

use crate::error::ContractError;

#[cw_serde]
pub enum Poll {
    Messages(WeightedPoll),
    ConfirmVerifierSet(WeightedPoll),
}

impl Poll {
    pub fn try_map<F, E>(self, func: F) -> Result<Self, E>
    where
        F: FnOnce(WeightedPoll) -> Result<WeightedPoll, E>,
        E: From<ContractError>,
    {
        match self {
            Poll::Messages(poll) => Ok(Poll::Messages(func(poll)?)),
            Poll::ConfirmVerifierSet(poll) => Ok(Poll::ConfirmVerifierSet(func(poll)?)),
        }
    }

    pub fn weighted_poll(self) -> WeightedPoll {
        match self {
            Poll::Messages(poll) | Poll::ConfirmVerifierSet(poll) => poll,
        }
    }
}
