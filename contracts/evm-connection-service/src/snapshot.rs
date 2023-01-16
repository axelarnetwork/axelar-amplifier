use std::{collections::HashMap, ops::Mul};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal, Decimal256, Fraction, Timestamp, Uint256, Uint64};

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

    pub fn get_participants_weight(&self) -> Uint256 {
        self.participants
            .iter()
            .fold(Uint256::zero(), |accum, item| {
                let (_, participant) = item;
                accum + participant.weight
            })
    }

    pub fn get_participant_weight(&self, voter: &Addr) -> Uint256 {
        let result = self.participants.get(voter);
        match result {
            Some(participant) => participant.weight,
            None => Uint256::zero(),
        }
    }

    pub fn calculate_min_passing_weight(&self, treshold: &Decimal) -> Uint256 {
        // TODO: check type sizes are correct, otherwise overflow may occur
        let t = Decimal256::from(*treshold);

        let min_passing_weight = self.bonded_weight * t;
        if min_passing_weight.mul(t.denominator()) >= self.bonded_weight.mul(t.denominator()) {
            return min_passing_weight;
        }

        min_passing_weight + Uint256::one()
    }
}
