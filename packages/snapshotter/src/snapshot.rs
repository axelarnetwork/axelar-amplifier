use std::{collections::HashMap, ops::Mul};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal, Decimal256, DepsMut, Fraction, Timestamp, Uint256, Uint64};
use service_registry::{msg::ActiveWorkers, state::Worker};

#[cw_serde]
pub struct Participant {
    pub address: Addr,
    pub weight: Uint256,
}

#[cw_serde]
pub struct Snapshot {
    pub timestamp: Timestamp,
    pub height: Uint64,
    pub total_weight: Uint256,
    pub participants: HashMap<String, Participant>,
}

impl Snapshot {
    pub fn new(
        deps: &DepsMut,
        timestamp: Timestamp,
        height: Uint64,
        active_workers: ActiveWorkers,
        filter_fn: impl Fn(&DepsMut, &Worker) -> bool,
        weight_fn: impl Fn(&DepsMut, &Worker) -> Option<Uint256>,
    ) -> Self {
        let mut total_weight: Uint256 = Uint256::zero();

        let mut participants: HashMap<String, Participant> = HashMap::new();

        for worker in active_workers.workers {
            let weight = weight_fn(deps, &worker);

            if weight.is_none() || !filter_fn(deps, &worker) {
                continue;
            }
            let weight = weight.unwrap();
            total_weight += weight;

            let participant = Participant {
                address: worker.address.clone(),
                weight,
            };
            participants.insert(worker.address.into_string(), participant);
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

    pub fn get_participant_weight(&self, voter: &String) -> Uint256 {
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
