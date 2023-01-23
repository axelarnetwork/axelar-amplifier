use std::ops::Mul;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    Addr, Decimal, Decimal256, Fraction, Isqrt, Order, Storage, Timestamp, Uint256, Uint64,
};
use service_registry::msg::ActiveWorkers;

use crate::state::{participants, Participant};

fn quadratic_weight(stake: Uint256) -> Uint256 {
    stake.isqrt()
}

#[cw_serde]
pub struct Snapshot {
    pub poll_id: Uint64,
    pub timestamp: Timestamp,
    pub height: Uint64,
    pub bonded_weight: Uint256,
}

impl Snapshot {
    pub fn new(
        store: &mut dyn Storage,
        poll_id: Uint64,
        timestamp: Timestamp,
        height: Uint64,
        active_workers: ActiveWorkers,
    ) -> Self {
        let mut bonded_weight: Uint256 = Uint256::zero();

        for worker in active_workers.workers {
            let weight = quadratic_weight(Uint256::from(worker.stake)); // TODO: apply power reduction?
            bonded_weight += weight;

            let participant = Participant {
                poll_id,
                address: worker.address.clone(),
                weight,
            };
            participants()
                .save(store, (poll_id.u64(), worker.address), &participant)
                .unwrap();
        }

        Self {
            poll_id,
            timestamp,
            height,
            bonded_weight,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn participants<'a>(
        &'a self,
        store: &'a mut dyn Storage,
    ) -> Box<(dyn Iterator<Item = Result<((u64, Addr), Participant), cosmwasm_std::StdError>> + '_)>
    {
        participants().idx.poll_id.prefix(self.poll_id.u64()).range(
            store,
            None,
            None,
            Order::Ascending,
        )
    }

    pub fn participant<'a>(
        &self,
        store: &'a mut dyn Storage,
        participant_address: &Addr,
    ) -> Option<Participant> {
        participants()
            .may_load(store, (self.poll_id.u64(), participant_address.clone()))
            .unwrap()
    }

    pub fn get_participants_weight(&self, store: &mut dyn Storage) -> Uint256 {
        self.participants(store)
            .fold(Uint256::zero(), |accum, item| {
                let (_, participant) = item.unwrap();
                accum + participant.weight
            })
    }

    pub fn get_participant_weight<'a>(&self, store: &'a mut dyn Storage, voter: &Addr) -> Uint256 {
        let result = self.participant(store, voter);
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
