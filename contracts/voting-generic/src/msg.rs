use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};

#[cw_serde]
pub struct PollResult {
    pub poll_id: String,
    pub results: Vec<bool>,
}

#[cw_serde]
pub struct Participant {
    pub address: Addr,
    pub weight: Uint256,
}

#[cw_serde]
pub enum ExecuteMsg {
    // generates and returns a poll ID
    StartPoll {
        participants: Vec<Participant>,
        block_height_expiry: u64, // all participants who don't vote before expiry have their votes defaulted to no
    },

    // returns a PollResult
    // errors if the poll is not finished
    EndPoll {
        poll_id: String,
    },

    // casts a vote(s) for poll_id
    // errors if sender is not a participant, if sender already voted, if poll doesn't exist, or if the poll is finished
    Vote {
        poll_id: String,
        votes: Vec<bool>, // can be changed to HexBinary to save space
    },
}
