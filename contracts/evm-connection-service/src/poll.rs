use cosmwasm_std::Uint256;

use crate::state::PollMetadata;

pub struct Poll {
    metadata: PollMetadata,
}

impl Poll {
    pub fn new(metadata: PollMetadata) -> Self {
        Self { metadata }
    }
}
