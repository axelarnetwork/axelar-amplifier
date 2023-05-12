use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};

use crate::{
    nonempty::NonEmptyVec,
    num::{NonZeroTimestamp, NonZeroUint256, NonZeroUint64},
    threshold::Threshold,
};

#[cw_serde]
pub struct Participant {
    pub address: Addr,
    pub weight: NonZeroUint256,
}

#[cw_serde]
pub struct Snapshot {
    pub timestamp: NonZeroTimestamp,
    pub height: NonZeroUint64,
    pub total_weight: NonZeroUint256,
    pub min_pass_weight: NonZeroUint256,
    pub participants: HashMap<String, Participant>,
}

impl Snapshot {
    pub fn new(
        timestamp: NonZeroTimestamp,
        height: NonZeroUint64,
        threshold: Threshold,
        participants: NonEmptyVec<Participant>,
    ) -> Self {
        let mut total_weight = Uint256::zero();

        let participants: Vec<Participant> = participants.into();
        let participants: HashMap<String, Participant> = participants
            .into_iter()
            .map(|participant| {
                total_weight += participant.weight.as_uint256();
                (participant.address.to_string(), participant)
            })
            .collect();

        // Unwrap won't panic here since it's impossible to have zero values when using NonEmptyVec of Participants with NonZero weight
        let min_pass_weight = NonZeroUint256::try_from(total_weight.mul_ceil(threshold)).unwrap();
        let total_weight = NonZeroUint256::try_from(total_weight).unwrap();

        Self {
            timestamp,
            height,
            total_weight,
            min_pass_weight,
            participants,
        }
    }

    pub fn get_participant_weight(&self, participant: &Addr) -> Option<&Uint256> {
        self.participants
            .get(participant.as_str())
            .map(|p| p.weight.as_uint256())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{from_binary, to_binary, Uint64};
    use rand::Rng;

    fn mock_participant(address: &str, weight: NonZeroUint256) -> Participant {
        Participant {
            address: Addr::unchecked(address),
            weight,
        }
    }

    fn mock_participants(participants: Vec<(&str, NonZeroUint256)>) -> NonEmptyVec<Participant> {
        let participants: Vec<Participant> = participants
            .into_iter()
            .map(|(address, weight)| mock_participant(address, weight))
            .collect();

        NonEmptyVec::try_from(participants).unwrap()
    }

    fn non_zero_256(value: impl Into<Uint256>) -> NonZeroUint256 {
        NonZeroUint256::try_from(value.into()).unwrap()
    }

    fn default_participants() -> NonEmptyVec<Participant> {
        mock_participants(vec![
            ("participant0", non_zero_256(100u16)),
            ("participant1", non_zero_256(100u16)),
            ("participant2", non_zero_256(100u16)),
            ("participant3", non_zero_256(100u16)),
            ("participant4", non_zero_256(200u16)),
            ("participant5", non_zero_256(200u16)),
            ("participant6", non_zero_256(300u16)),
            ("participant7", non_zero_256(300u16)),
            ("participant8", non_zero_256(300u16)),
            ("participant9", non_zero_256(300u16)),
        ])
    }

    #[test]
    fn test_valid_snapshot() {
        let mut rng = rand::thread_rng();

        let timestamp = NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap();
        let height = NonZeroUint64::try_from(rng.gen::<u64>()).unwrap();
        let threshold = Threshold::try_from_ratio(2u8, 3u8).unwrap();

        let result = Snapshot::new(
            timestamp.clone(),
            height.clone(),
            threshold,
            default_participants(),
        );

        assert_eq!(result.timestamp, timestamp);
        assert_eq!(result.height, height);
        assert_eq!(
            result.total_weight,
            NonZeroUint256::try_from(Uint256::from(2000u16)).unwrap()
        );
        assert_eq!(
            result.min_pass_weight,
            NonZeroUint256::try_from(Uint256::from(1334u16)).unwrap()
        );
        assert_eq!(result.participants.len(), 10);
    }

    #[test]
    fn test_snapshot_serialization() {
        let mut rng = rand::thread_rng();

        let snapshot = Snapshot::new(
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            Threshold::try_from_ratio(2u8, 3u8).unwrap(),
            default_participants(),
        );

        let serialized = to_binary(&snapshot).unwrap();
        let deserialized: Snapshot = from_binary(&serialized).unwrap();

        assert_eq!(snapshot, deserialized);
    }

    #[test]
    fn test_min_passing_weight_one_third() {
        let mut rng = rand::thread_rng();

        let snapshot = Snapshot::new(
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            Threshold::try_from_ratio(1u8, 3u8).unwrap(),
            default_participants(),
        );

        assert_eq!(
            snapshot.min_pass_weight,
            NonZeroUint256::try_from(Uint256::from(667u32)).unwrap()
        );
    }

    #[test]
    fn test_min_passing_weight_total_weight() {
        let mut rng = rand::thread_rng();

        let snapshot = Snapshot::new(
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            Threshold::try_from_ratio(1u8, 1u8).unwrap(),
            default_participants(),
        );

        assert_eq!(snapshot.min_pass_weight, snapshot.total_weight);
    }

    #[test]
    fn test_min_passing_weight_ceil() {
        let mut rng = rand::thread_rng();

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
                let participants = mock_participants(vec![(
                    "participant",
                    NonZeroUint256::try_from(total_weight).unwrap(),
                )]);

                let snapshot = Snapshot::new(
                    NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
                    NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
                    Threshold::try_from_ratio(2u8, 3u8).unwrap(),
                    participants,
                );

                assert_eq!(
                    snapshot.min_pass_weight,
                    NonZeroUint256::try_from(expected_passing_weight).unwrap(),
                    "total_weight: {}, expected_passing_weight: {}",
                    total_weight,
                    expected_passing_weight
                );
            });
    }

    #[test]
    fn test_min_passing_weight_no_overflow() {
        let mut rng = rand::thread_rng();

        let participants = mock_participants(vec![(
            "participant",
            NonZeroUint256::try_from(Uint256::MAX).unwrap(),
        )]);

        let snapshot = Snapshot::new(
            NonZeroTimestamp::try_from_nanos(rng.gen()).unwrap(),
            NonZeroUint64::try_from(rng.gen::<u64>()).unwrap(),
            Threshold::try_from_ratio(Uint64::MAX, Uint64::MAX).unwrap(),
            participants,
        );

        assert_eq!(snapshot.min_pass_weight, snapshot.total_weight);
    }
}
