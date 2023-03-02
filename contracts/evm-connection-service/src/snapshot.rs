use std::{collections::HashMap, ops::Mul};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal, Decimal256, Fraction, Storage, Timestamp, Uint256, Uint64};
use service_registry::msg::ActiveWorkers;

use crate::state::{Participant, WORKERS_VOTING_POWER};

#[cw_serde]
pub struct Snapshot {
    pub timestamp: Timestamp,
    pub height: Uint64,
    pub total_weight: Uint256,
    pub participants: HashMap<Addr, Participant>,
}

impl Snapshot {
    pub fn new(
        store: &mut dyn Storage,
        timestamp: Timestamp,
        height: Uint64,
        active_workers: ActiveWorkers,
    ) -> Self {
        let mut total_weight: Uint256 = Uint256::zero();

        let mut participants: HashMap<Addr, Participant> = HashMap::new();

        for worker in active_workers.workers {
            let weight = WORKERS_VOTING_POWER
                .may_load(store, worker.address.clone())
                .unwrap();

            if weight.is_none() {
                continue;
            }
            let weight = weight.unwrap();
            total_weight += weight;

            let participant = Participant {
                address: worker.address.clone(),
                weight,
            };
            participants.insert(worker.address, participant);
        }

        Self {
            timestamp,
            height,
            total_weight,
            participants,
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

        let min_passing_weight = self.total_weight * t;
        if min_passing_weight.mul(t.denominator()) >= self.total_weight.mul(t.denominator()) {
            return min_passing_weight;
        }

        min_passing_weight + Uint256::one()
    }
}
