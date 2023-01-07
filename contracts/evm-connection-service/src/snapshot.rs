use std::{collections::HashMap, ops::Mul};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal256, Fraction, Timestamp, Uint256, Uint64};

use crate::state::Participant;

#[cw_serde]
pub struct Snapshot {
    pub timestamp: Timestamp,
    pub height: Uint64,
    pub participants: HashMap<Addr, Participant>,
    pub bonded_weight: Uint256,
}

impl Snapshot {
    pub fn new(
        timestamp: Timestamp,
        height: Uint64,
        participants: HashMap<Addr, Participant>,
        bonded_weight: Uint256,
    ) -> Self {
        Self {
            timestamp,
            height,
            participants,
            bonded_weight,
        }
    }

    pub fn calculate_min_passing_weight(&self, treshold: Decimal256) -> Uint256 {
        // TODO: check type sizes are correct, otherwise overflow may occur

        let min_passing_weight = self.bonded_weight * treshold;
        if min_passing_weight.mul(treshold.denominator())
            >= self.bonded_weight.mul(treshold.denominator())
        {
            return min_passing_weight;
        }

        min_passing_weight + Uint256::one()
    }
}
