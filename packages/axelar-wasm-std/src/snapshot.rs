use std::{collections::HashMap, ops::Mul};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal, Decimal256, DepsMut, Uint256};
use service_registry::state::Worker;

use crate::{
    error::SnapshotError,
    nonzero::{NonZeroTimestamp, NonZeroUint64},
};

#[cw_serde]
pub struct Participant {
    pub address: Addr,
    pub weight: Uint256,
}

#[cw_serde]
pub struct Snapshot {
    pub timestamp: NonZeroTimestamp,
    pub height: NonZeroUint64,
    pub total_weight: Uint256,
    pub participants: HashMap<String, Participant>,
}

impl Snapshot {
    pub fn new(
        deps: &DepsMut,
        timestamp: NonZeroTimestamp,
        height: NonZeroUint64,
        candidates: Vec<Worker>,
        filter_fn: impl Fn(&DepsMut, &Worker) -> bool,
        weight_fn: impl Fn(&DepsMut, &Worker) -> Option<Uint256>,
    ) -> Result<Self, SnapshotError> {
        let mut total_weight: Uint256 = Uint256::zero();
        let mut participants: HashMap<String, Participant> = HashMap::new();

        for worker in candidates {
            let weight = weight_fn(deps, &worker).unwrap_or(Uint256::zero());

            if weight.is_zero() || !filter_fn(deps, &worker) {
                continue;
            }

            total_weight += weight;

            let participant = Participant {
                address: worker.address.clone(),
                weight,
            };
            participants.insert(worker.address.into_string(), participant);
        }

        if participants.is_empty() {
            return Err(SnapshotError::NoParticipants {});
        }

        Ok(Self {
            timestamp,
            height,
            total_weight,
            participants,
        })
    }

    pub fn get_participant_weight(&self, participant: &Addr) -> Option<Uint256> {
        self.participants
            .get(participant.as_str())
            .map(|p| p.weight)
    }

    pub fn calculate_min_passing_weight(&self, threshold: &Decimal) -> Uint256 {
        // TODO: check type sizes are correct, otherwise overflow may occur
        let threshold = Decimal256::from(*threshold);

        Decimal256::from_ratio(self.total_weight, Uint256::one())
            .mul(threshold)
            .to_uint_ceil()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{from_binary, testing::mock_dependencies, to_binary, Uint128};
    use rand::Rng;
    use service_registry::state::WorkerState;

    fn mock_worker(address: &str, stake: Uint128) -> Worker {
        Worker {
            address: Addr::unchecked(address),
            stake,
            commission_rate: Uint128::zero(),
            state: WorkerState::Active,
            service_name: "service".to_string(),
        }
    }

    fn mock_workers(workers: Vec<(&str, Uint128)>) -> Vec<Worker> {
        workers
            .into_iter()
            .map(|(address, stake)| mock_worker(address, stake))
            .collect()
    }

    fn default_workers() -> Vec<Worker> {
        mock_workers(vec![
            ("worker0", Uint128::from(100u128)),
            ("worker1", Uint128::from(100u128)),
            ("worker2", Uint128::from(100u128)),
            ("worker3", Uint128::from(100u128)),
            ("worker4", Uint128::from(200u128)),
            ("worker5", Uint128::from(200u128)),
            ("worker6", Uint128::from(300u128)),
            ("worker7", Uint128::from(300u128)),
            ("worker8", Uint128::from(300u128)),
            ("worker9", Uint128::from(300u128)),
        ])
    }

    fn default_filter_function() -> impl Fn(&DepsMut, &Worker) -> bool {
        &|_: &DepsMut, _: &Worker| -> bool { true }
    }

    fn default_weight_function() -> impl Fn(&DepsMut, &Worker) -> Option<Uint256> {
        &|_: &DepsMut, worker: &Worker| -> Option<Uint256> { Some(Uint256::from(worker.stake)) }
    }

    #[test]
    fn test_valid_snapshot() {
        let mut deps = mock_dependencies();
        let mut rng = rand::thread_rng();

        let result = Snapshot::new(
            &deps.as_mut(),
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            default_workers(),
            default_filter_function(),
            default_weight_function(),
        );

        assert!(result.is_ok())
    }

    #[test]
    fn test_filter_function() {
        let mut deps = mock_dependencies();
        let mut rng = rand::thread_rng();

        let filter_fn =
            &|_: &DepsMut, worker: &Worker| -> bool { worker.stake >= Uint128::from(200u128) };

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            default_workers(),
            filter_fn,
            default_weight_function(),
        )
        .unwrap();

        assert_eq!(snapshot.participants.len(), 6);
    }

    #[test]
    fn test_weight_function() {
        let mut deps = mock_dependencies();
        let mut rng = rand::thread_rng();

        let weight_fn = &|_: &DepsMut, _: &Worker| -> Option<Uint256> { Some(Uint256::one()) };

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            default_workers(),
            default_filter_function(),
            weight_fn,
        )
        .unwrap();

        assert_eq!(
            snapshot.total_weight,
            Uint256::from(snapshot.participants.len() as u32)
        );
    }

    #[test]
    fn test_filter_zero_weight_candidates() {
        let mut deps = mock_dependencies();
        let mut rng = rand::thread_rng();

        let weight_fn = &|_: &DepsMut, worker: &Worker| -> Option<Uint256> {
            if worker.stake < Uint128::from(200u128) {
                Some(Uint256::zero())
            } else {
                Some(Uint256::one())
            }
        };

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            default_workers(),
            default_filter_function(),
            weight_fn,
        )
        .unwrap();

        assert_eq!(snapshot.participants.len(), 6);
    }

    #[test]
    fn test_error_no_participants() {
        let mut deps = mock_dependencies();
        let mut rng = rand::thread_rng();

        let filter_fn = &|_: &DepsMut, _: &Worker| -> bool { false };

        let result = Snapshot::new(
            &deps.as_mut(),
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            default_workers(),
            filter_fn,
            default_weight_function(),
        );

        assert_eq!(
            result.unwrap_err().to_string(),
            SnapshotError::NoParticipants.to_string()
        );
    }

    #[test]
    fn test_snapshot_serialization() {
        let mut deps = mock_dependencies();
        let mut rng = rand::thread_rng();

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            default_workers(),
            default_filter_function(),
            |_, _| Some(Uint256::from(100u32)),
        )
        .unwrap();

        let serialized = to_binary(&snapshot).unwrap();
        let deserialized: Snapshot = from_binary(&serialized).unwrap();

        assert_eq!(snapshot, deserialized);
    }

    #[test]
    fn test_min_passing_weight_one_third() {
        let mut deps = mock_dependencies();
        let mut rng = rand::thread_rng();

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            default_workers(),
            default_filter_function(),
            |_, _| Some(Uint256::from(1u32)),
        )
        .unwrap();

        let threshold = Decimal::from_ratio(Uint128::one(), Uint128::from(3u32));
        assert_eq!(
            snapshot.calculate_min_passing_weight(&threshold),
            Uint256::from(4u32)
        );
    }

    #[test]
    fn test_min_passing_weight_total_weight() {
        let mut deps = mock_dependencies();
        let mut rng = rand::thread_rng();

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            default_workers(),
            default_filter_function(),
            default_weight_function(),
        )
        .unwrap();

        let threshold = Decimal::from_ratio(Uint128::one(), Uint128::one());
        assert_eq!(
            snapshot.calculate_min_passing_weight(&threshold),
            snapshot.total_weight
        );
    }

    #[test]
    fn test_min_passing_weight_ceil() {
        let mut deps = mock_dependencies();
        let mut rng = rand::thread_rng();

        let mut snapshot = Snapshot::new(
            &deps.as_mut(),
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            default_workers(),
            default_filter_function(),
            default_weight_function(),
        )
        .unwrap();

        let threshold = Decimal::from_ratio(2u8, 3u8);

        // (total_weight, min_passing_weight)
        let test_data = [
            (Uint256::from(300u16), Uint256::from(200u16)),
            (Uint256::from(299u16), Uint256::from(200u16)),
            (Uint256::from(301u16), Uint256::from(201u16)),
            (Uint256::from(297u16), Uint256::from(198u16)),
            (Uint256::from(298u16), Uint256::from(199u16)),
            (Uint256::from(302u16), Uint256::from(202u16)),
        ];

        test_data
            .into_iter()
            .for_each(|(total_weight, expected_passing_weight)| {
                snapshot.total_weight = total_weight;
                assert_eq!(
                    snapshot.calculate_min_passing_weight(&threshold),
                    expected_passing_weight,
                    "multiplier: {}, expected_ceil: {}",
                    total_weight,
                    expected_passing_weight
                );
            });
    }
}
