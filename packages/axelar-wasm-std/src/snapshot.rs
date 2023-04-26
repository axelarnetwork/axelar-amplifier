use std::{collections::HashMap, ops::Mul};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal, Decimal256, DepsMut, Fraction, Timestamp, Uint256, Uint64};
use service_registry::state::Worker;

use crate::error::SnapshotError;

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
        candidates: Vec<Worker>,
        filter_fn: impl Fn(&DepsMut, &Worker) -> bool,
        weight_fn: impl Fn(&DepsMut, &Worker) -> Option<Uint256>,
    ) -> Result<Self, SnapshotError> {
        if height.is_zero() {
            return Err(SnapshotError::ZeroHeight {});
        }
        if timestamp.nanos() == 0 {
            return Err(SnapshotError::ZeroTimestamp {});
        }

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

    pub fn get_participant_weight(&self, participant: &Addr) -> Uint256 {
        match self.participants.get(participant.as_str()) {
            Some(participant) => participant.weight,
            None => Uint256::zero(),
        }
    }

    pub fn calculate_min_passing_weight(&self, threshold: &Decimal) -> Uint256 {
        // TODO: check type sizes are correct, otherwise overflow may occur
        let threshold = Decimal256::from(*threshold);

        let min_passing_weight = self.total_weight * threshold;
        if min_passing_weight.mul(threshold.denominator())
            >= self.total_weight.mul(threshold.numerator())
        {
            min_passing_weight
        } else {
            min_passing_weight + Uint256::one()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{from_binary, testing::mock_dependencies, to_binary, Uint128};
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

        let timestamp = Timestamp::from_seconds(1682460479);
        let height = Uint64::from(5u32);

        let result = Snapshot::new(
            &deps.as_mut(),
            timestamp,
            height,
            default_workers(),
            default_filter_function(),
            default_weight_function(),
        );

        assert!(result.is_ok())
    }

    #[test]
    fn test_filter_function() {
        let mut deps = mock_dependencies();

        let timestamp = Timestamp::from_seconds(1682460479);
        let height = Uint64::from(5u32);

        let filter_fn =
            &|_: &DepsMut, worker: &Worker| -> bool { worker.stake >= Uint128::from(200u128) };

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            timestamp,
            height,
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

        let timestamp = Timestamp::from_seconds(1682460479);
        let height = Uint64::from(5u32);

        let weight_fn = &|_: &DepsMut, _: &Worker| -> Option<Uint256> { Some(Uint256::one()) };

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            timestamp,
            height,
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

        let timestamp = Timestamp::from_seconds(1682460479);
        let height = Uint64::from(5u32);

        let weight_fn = &|_: &DepsMut, worker: &Worker| -> Option<Uint256> {
            if worker.stake < Uint128::from(200u128) {
                Some(Uint256::zero())
            } else {
                Some(Uint256::one())
            }
        };

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            timestamp,
            height,
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

        let timestamp = Timestamp::from_seconds(1682460479);
        let height = Uint64::from(5u32);

        let filter_fn = &|_: &DepsMut, _: &Worker| -> bool { false };

        let result = Snapshot::new(
            &deps.as_mut(),
            timestamp,
            height,
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
    fn test_error_zero_height() {
        let mut deps = mock_dependencies();

        let timestamp = Timestamp::from_seconds(1682460479);
        let height = Uint64::zero();

        let result = Snapshot::new(
            &deps.as_mut(),
            timestamp,
            height,
            default_workers(),
            default_filter_function(),
            default_weight_function(),
        );

        assert_eq!(
            result.unwrap_err().to_string(),
            SnapshotError::ZeroHeight.to_string()
        );
    }

    #[test]
    fn test_error_zero_timestamp() {
        let mut deps = mock_dependencies();

        let timestamp = Timestamp::from_seconds(0);
        let height = Uint64::from(5u32);

        let result = Snapshot::new(
            &deps.as_mut(),
            timestamp,
            height,
            default_workers(),
            default_filter_function(),
            default_weight_function(),
        );

        assert_eq!(
            result.unwrap_err().to_string(),
            SnapshotError::ZeroTimestamp.to_string()
        );
    }

    #[test]
    fn test_snapshot_serialization() {
        let mut deps = mock_dependencies();

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            Timestamp::from_seconds(1682460479),
            Uint64::from(5u32),
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

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            Timestamp::from_seconds(1682460479),
            Uint64::from(5u32),
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

        let snapshot = Snapshot::new(
            &deps.as_mut(),
            Timestamp::from_seconds(1682460479),
            Uint64::from(5u32),
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
}
