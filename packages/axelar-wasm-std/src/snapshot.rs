use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};

use crate::{nonempty, threshold::MajorityThreshold};

#[cw_serde]
pub struct Participant {
    pub address: Addr,
    pub weight: nonempty::Uint256,
}

#[cw_serde]
pub struct Snapshot {
    pub quorum: nonempty::Uint256,
    pub participants: HashMap<String, Participant>,
}

impl Snapshot {
    pub fn new(
        quorum_threshold: MajorityThreshold,
        participants: nonempty::Vec<Participant>,
    ) -> Self {
        let mut total_weight = Uint256::zero();

        let participants: Vec<Participant> = participants.into();
        let participants: HashMap<String, Participant> = participants
            .into_iter()
            .map(|participant| {
                let weight: &Uint256 = participant.weight.as_ref();
                total_weight += weight;

                (participant.address.to_string(), participant)
            })
            .collect();

        // Shouldn't panic here since it's impossible to have zero values when using nonempty::Vec of Participants with NonZero weight
        let quorum = nonempty::Uint256::try_from(total_weight.mul_ceil(quorum_threshold))
            .expect("violated invariant: quorum is zero");

        Self {
            quorum,
            participants,
        }
    }

    pub fn get_participant_weight(&self, participant: &Addr) -> Option<&Uint256> {
        self.participants
            .get(participant.as_str())
            .map(|p| p.weight.as_ref())
    }

    pub fn get_participants(&self) -> Vec<Addr> {
        self.participants
            .keys()
            .cloned()
            .map(Addr::unchecked)
            .collect()
    }

    pub fn get_participant(&self, participant: &Addr) -> Option<&Participant> {
        self.participants.get(&participant.to_string())
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{from_binary, to_binary, Uint64};

    use crate::Threshold;

    use super::*;

    fn mock_participant(address: &str, weight: nonempty::Uint256) -> Participant {
        Participant {
            address: Addr::unchecked(address),
            weight,
        }
    }

    fn mock_participants(
        participants: Vec<(&str, nonempty::Uint256)>,
    ) -> nonempty::Vec<Participant> {
        let participants: Vec<Participant> = participants
            .into_iter()
            .map(|(address, weight)| mock_participant(address, weight))
            .collect();

        nonempty::Vec::try_from(participants).unwrap()
    }

    fn non_zero_256(value: impl Into<Uint256>) -> nonempty::Uint256 {
        nonempty::Uint256::try_from(value.into()).unwrap()
    }

    fn default_participants() -> nonempty::Vec<Participant> {
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
        let numerator: nonempty::Uint64 = Uint64::from(2u8).try_into().unwrap();
        let denominator: nonempty::Uint64 = Uint64::from(3u8).try_into().unwrap();
        let threshold: Threshold = (numerator, denominator).try_into().unwrap();

        let result = Snapshot::new(threshold.try_into().unwrap(), default_participants());

        assert_eq!(
            result.quorum,
            nonempty::Uint256::try_from(Uint256::from(1334u16)).unwrap()
        );
        assert_eq!(result.participants.len(), 10);
    }

    #[test]
    fn test_snapshot_serialization() {
        let snapshot = Snapshot::new(
            Threshold::try_from((2u64, 3u64))
                .unwrap()
                .try_into()
                .unwrap(),
            default_participants(),
        );

        let serialized = to_binary(&snapshot).unwrap();
        let deserialized: Snapshot = from_binary(&serialized).unwrap();

        assert_eq!(snapshot, deserialized);
    }

    #[test]
    fn test_quorum_two_thirds() {
        let snapshot = Snapshot::new(
            Threshold::try_from((2u64, 3u64))
                .unwrap()
                .try_into()
                .unwrap(),
            default_participants(),
        );

        assert_eq!(
            snapshot.quorum,
            nonempty::Uint256::try_from(Uint256::from(1334u32)).unwrap()
        );
    }

    #[test]
    fn test_quorum_is_total_weight() {
        let total_weight = Into::<Vec<Participant>>::into(default_participants())
            .iter()
            .fold(Uint256::zero(), |acc, p| acc + Uint256::from(p.weight))
            .try_into()
            .unwrap();

        let snapshot = Snapshot::new(
            Threshold::try_from((1u64, 1u64))
                .unwrap()
                .try_into()
                .unwrap(),
            default_participants(),
        );

        assert_eq!(snapshot.quorum, total_weight);
    }

    #[test]
    fn test_quorum_ceil() {
        // (total_weight, quorum)
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
            .for_each(|(total_weight, expected_quorum)| {
                let participants = mock_participants(vec![(
                    "participant",
                    nonempty::Uint256::try_from(total_weight).unwrap(),
                )]);

                let snapshot = Snapshot::new(
                    Threshold::try_from((2u64, 3u64))
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    participants,
                );

                assert_eq!(
                    snapshot.quorum,
                    nonempty::Uint256::try_from(expected_quorum).unwrap(),
                    "total_weight: {}, expected_quorum: {}",
                    total_weight,
                    expected_quorum
                );
            });
    }

    #[test]
    fn test_quorum_no_overflow() {
        let participants = mock_participants(vec![(
            "participant",
            nonempty::Uint256::try_from(Uint256::MAX).unwrap(),
        )]);

        let snapshot = Snapshot::new(
            Threshold::try_from((Uint64::MAX, Uint64::MAX))
                .unwrap()
                .try_into()
                .unwrap(),
            participants,
        );

        assert_eq!(Uint256::from(snapshot.quorum), Uint256::MAX);
    }
}
