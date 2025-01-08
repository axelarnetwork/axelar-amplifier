use std::str::FromStr;
use std::vec::Vec;

use axelar_wasm_std::address::AddressFormat;
use axelar_wasm_std::msg_id::{
    Base58SolanaTxSignatureAndEventIndex, Base58TxDigestAndEventIndex, Bech32mFormat,
    FieldElementAndEventIndex, HexTxHash, HexTxHashAndEventIndex, MessageIdFormat,
};
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, IntoEvent, MajorityThreshold, VerificationStatus};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Empty};
use multisig::verifier_set::VerifierSet;
use router_api::{Address, ChainName, Message};
use serde::Serialize;

use crate::error::ContractError;

#[derive(Serialize, IntoEvent)]
pub enum Event<T>
where
    T: Serialize,
{
    Instantiated {
        service_registry_contract: Addr,
        service_name: nonempty::String,
        source_gateway_address: nonempty::String,
        voting_threshold: MajorityThreshold,
        block_expiry: nonempty::Uint64,
        confirmation_height: u64,
        source_chain: ChainName,
        rewards_contract: Addr,
        msg_id_format: MessageIdFormat,
        address_format: AddressFormat,
    },
    MessagesPollStarted {
        messages: Vec<TxEventConfirmation>,
        poll_id: PollId,
        source_chain: ChainName,
        source_gateway_address: nonempty::String,
        confirmation_height: u64,
        expires_at: u64,
        participants: Vec<Addr>,
    },
    VerifierSetPollStarted {
        verifier_set: VerifierSetConfirmation,
        poll_id: PollId,
        source_chain: ChainName,
        source_gateway_address: nonempty::String,
        confirmation_height: u64,
        expires_at: u64,
        participants: Vec<Addr>,
    },
    QuorumReached {
        content: T,
        status: VerificationStatus,
        poll_id: PollId,
    },
    Voted {
        poll_id: PollId,
        voter: Addr,
        votes: Vec<Vote>,
    },
    PollEnded {
        poll_id: PollId,
        source_chain: ChainName,
        results: Vec<Option<Vote>>,
    },
}

pub type EmptyEvent = Event<Empty>;

#[cw_serde]
pub struct VerifierSetConfirmation {
    #[deprecated(since = "1.1.0", note = "use message_id field instead")]
    pub tx_id: nonempty::String,
    #[deprecated(since = "1.1.0", note = "use message_id field instead")]
    pub event_index: u32,
    pub message_id: nonempty::String,
    pub verifier_set: VerifierSet,
}

/// If parsing is successful, returns (tx_id, event_index). Otherwise returns ContractError::InvalidMessageID
#[deprecated(since = "1.1.0", note = "don't parse message id, just emit as is")]
fn parse_message_id(
    message_id: &str,
    msg_id_format: &MessageIdFormat,
) -> Result<(nonempty::String, u32), ContractError> {
    match msg_id_format {
        MessageIdFormat::Base58TxDigestAndEventIndex => {
            let id = Base58TxDigestAndEventIndex::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?;
            Ok((
                id.tx_digest_as_base58(),
                u32::try_from(id.event_index)
                    .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?,
            ))
        }
        MessageIdFormat::FieldElementAndEventIndex => {
            let id = FieldElementAndEventIndex::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?;

            Ok((
                id.tx_hash_as_hex(),
                u32::try_from(id.event_index)
                    .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?,
            ))
        }
        MessageIdFormat::HexTxHashAndEventIndex => {
            let id = HexTxHashAndEventIndex::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?;

            Ok((
                id.tx_hash_as_hex(),
                u32::try_from(id.event_index)
                    .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?,
            ))
        }
        MessageIdFormat::Base58SolanaTxSignatureAndEventIndex => {
            let id = Base58SolanaTxSignatureAndEventIndex::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?;

            Ok((
                id.signature_as_base58(),
                u32::try_from(id.event_index)
                    .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?,
            ))
        }
        MessageIdFormat::HexTxHash => {
            let id = HexTxHash::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.into()))?;

            Ok((id.tx_hash_as_hex(), 0))
        }
        MessageIdFormat::Bech32m { prefix, length } => {
            let bech32m_message_id = Bech32mFormat::from_str(prefix, *length as usize, message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.into()))?;
            Ok((bech32m_message_id.to_string().try_into()?, 0))
        }
    }
}

impl VerifierSetConfirmation {
    pub fn new(
        message_id: nonempty::String,
        msg_id_format: MessageIdFormat,
        verifier_set: VerifierSet,
    ) -> Result<Self, ContractError> {
        #[allow(deprecated)]
        let (tx_id, event_index) = parse_message_id(&message_id, &msg_id_format)?;

        #[allow(deprecated)]
        // TODO: remove this attribute when tx_id and event_index are removed from the event
        Ok(Self {
            tx_id,
            event_index,
            message_id,
            verifier_set,
        })
    }
}

#[cw_serde]
pub struct TxEventConfirmation {
    #[deprecated(since = "1.1.0", note = "use message_id field instead")]
    pub tx_id: nonempty::String,
    #[deprecated(since = "1.1.0", note = "use message_id field instead")]
    pub event_index: u32,
    pub message_id: nonempty::String,
    pub destination_address: Address,
    pub destination_chain: ChainName,
    pub source_address: Address,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub payload_hash: [u8; 32],
}

impl TryFrom<(Message, &MessageIdFormat)> for TxEventConfirmation {
    type Error = ContractError;
    fn try_from((msg, msg_id_format): (Message, &MessageIdFormat)) -> Result<Self, Self::Error> {
        #[allow(deprecated)]
        let (tx_id, event_index) = parse_message_id(&msg.cc_id.message_id, msg_id_format)?;

        #[allow(deprecated)]
        // TODO: remove this attribute when tx_id and event_index are removed from the event
        Ok(TxEventConfirmation {
            tx_id,
            event_index,
            message_id: msg.cc_id.message_id,
            destination_address: msg.destination_address,
            destination_chain: msg.destination_chain,
            source_address: msg.source_address,
            payload_hash: msg.payload_hash,
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use axelar_wasm_std::address::AddressFormat;
    use axelar_wasm_std::msg_id::{
        Base58TxDigestAndEventIndex, HexTxHash, HexTxHashAndEventIndex, MessageIdFormat,
    };
    use axelar_wasm_std::voting::Vote;
    use axelar_wasm_std::{nonempty, Threshold, VerificationStatus};
    use cosmwasm_std::testing::MockApi;
    use cosmwasm_std::{Attribute, Uint128};
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use multisig::verifier_set::VerifierSet;
    use router_api::{CrossChainId, Message};
    use serde_json::json;

    use super::{TxEventConfirmation, VerifierSetConfirmation};
    use crate::events::{PollEnded, PollMetadata, PollStarted, QuorumReached, Voted};
    use crate::state::Config;

    fn random_32_bytes() -> [u8; 32] {
        let mut bytes = [0; 32];
        for b in &mut bytes {
            *b = rand::random();
        }
        bytes
    }

    fn generate_msg(msg_id: nonempty::String) -> Message {
        Message {
            cc_id: CrossChainId::new("source-chain", msg_id).unwrap(),
            source_address: "source-address".parse().unwrap(),
            destination_chain: "destination-chain".parse().unwrap(),
            destination_address: "destination-address".parse().unwrap(),
            payload_hash: [0; 32],
        }
    }

    fn compare_event_to_message(event: TxEventConfirmation, msg: Message) {
        assert_eq!(event.source_address, msg.source_address);
        assert_eq!(event.destination_address, msg.destination_address);
        assert_eq!(event.destination_chain, msg.destination_chain);
        assert_eq!(event.payload_hash, msg.payload_hash);
    }

    #[test]
    fn should_make_tx_event_confirmation_with_hex_event_index_msg_id() {
        let msg_id = HexTxHashAndEventIndex {
            tx_hash: random_32_bytes(),
            event_index: 0,
        };
        let msg = generate_msg(msg_id.to_string().parse().unwrap());

        let event =
            TxEventConfirmation::try_from((msg.clone(), &MessageIdFormat::HexTxHashAndEventIndex))
                .unwrap();

        assert_eq!(event.message_id, msg.cc_id.message_id);
        compare_event_to_message(event, msg);
    }

    #[test]
    fn should_make_tx_event_confirmation_with_hex_msg_id() {
        let msg_id = HexTxHash {
            tx_hash: random_32_bytes(),
        };
        let msg = generate_msg(msg_id.to_string().parse().unwrap());

        let event =
            TxEventConfirmation::try_from((msg.clone(), &MessageIdFormat::HexTxHash)).unwrap();

        assert_eq!(event.message_id, msg.cc_id.message_id);
        compare_event_to_message(event, msg);
    }

    #[test]
    fn should_make_tx_event_confirmation_with_base58_msg_id() {
        let msg_id = Base58TxDigestAndEventIndex {
            tx_digest: random_32_bytes(),
            event_index: 0,
        };
        let msg = generate_msg(msg_id.to_string().parse().unwrap());

        let event = TxEventConfirmation::try_from((
            msg.clone(),
            &MessageIdFormat::Base58TxDigestAndEventIndex,
        ))
        .unwrap();

        assert_eq!(event.message_id, msg.cc_id.message_id);
        compare_event_to_message(event, msg);
    }

    #[test]
    fn make_tx_event_confirmation_should_fail_with_invalid_message_id() {
        let msg = generate_msg("foobar".parse().unwrap());
        let event =
            TxEventConfirmation::try_from((msg.clone(), &MessageIdFormat::HexTxHashAndEventIndex));
        assert!(event.is_err());
    }

    #[test]
    fn make_tx_event_confirmation_should_fail_with_wrong_format_message_id() {
        let msg_id = HexTxHashAndEventIndex {
            tx_hash: random_32_bytes(),
            event_index: 0,
        };
        let msg = generate_msg(msg_id.to_string().parse().unwrap());

        let event = TxEventConfirmation::try_from((
            msg.clone(),
            &MessageIdFormat::Base58TxDigestAndEventIndex,
        ));
        assert!(event.is_err());
    }

    #[test]
    fn should_make_verifier_set_confirmation_with_hex_msg_id() {
        let msg_id = HexTxHashAndEventIndex {
            tx_hash: random_32_bytes(),
            event_index: rand::random::<u32>() as u64,
        };
        let verifier_set = VerifierSet {
            signers: BTreeMap::new(),
            threshold: Uint128::one(),
            created_at: 1,
        };
        let event = VerifierSetConfirmation::new(
            msg_id.to_string().parse().unwrap(),
            MessageIdFormat::HexTxHashAndEventIndex,
            verifier_set.clone(),
        )
        .unwrap();

        assert_eq!(event.message_id, msg_id.to_string().try_into().unwrap());
        assert_eq!(event.verifier_set, verifier_set);
    }

    #[test]
    fn should_make_verifier_set_confirmation_with_base58_msg_id() {
        let msg_id = Base58TxDigestAndEventIndex {
            tx_digest: random_32_bytes(),
            event_index: rand::random::<u32>() as u64,
        };
        let verifier_set = VerifierSet {
            signers: BTreeMap::new(),
            threshold: Uint128::one(),
            created_at: 1,
        };
        let event = VerifierSetConfirmation::new(
            msg_id.to_string().parse().unwrap(),
            MessageIdFormat::Base58TxDigestAndEventIndex,
            verifier_set.clone(),
        )
        .unwrap();

        assert_eq!(event.message_id, msg_id.to_string().try_into().unwrap());
        assert_eq!(event.verifier_set, verifier_set);
    }

    #[test]
    fn make_verifier_set_confirmation_should_fail_with_invalid_message_id() {
        let msg_id = "foobar";
        let verifier_set = VerifierSet {
            signers: BTreeMap::new(),
            threshold: Uint128::one(),
            created_at: 1,
        };

        let event = VerifierSetConfirmation::new(
            msg_id.to_string().parse().unwrap(),
            MessageIdFormat::Base58TxDigestAndEventIndex,
            verifier_set,
        );
        assert!(event.is_err());
    }

    #[test]
    fn make_verifier_set_confirmation_should_fail_with_different_msg_id_format() {
        let msg_id = HexTxHashAndEventIndex {
            tx_hash: random_32_bytes(),
            event_index: rand::random::<u64>(),
        };
        let verifier_set = VerifierSet {
            signers: BTreeMap::new(),
            threshold: Uint128::one(),
            created_at: 1,
        };

        let event = VerifierSetConfirmation::new(
            msg_id.to_string().parse().unwrap(),
            MessageIdFormat::Base58TxDigestAndEventIndex,
            verifier_set,
        );
        assert!(event.is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn events_should_not_change() {
        let api = MockApi::default();

        let config = Config {
            service_name: "serviceName".try_into().unwrap(),
            service_registry_contract: api.addr_make("serviceRegistry_contract"),
            source_gateway_address: "sourceGatewayAddress".try_into().unwrap(),
            voting_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            block_expiry: 10u64.try_into().unwrap(),
            confirmation_height: 1,
            source_chain: "sourceChain".try_into().unwrap(),
            rewards_contract: api.addr_make("rewardsContract"),
            msg_id_format: MessageIdFormat::HexTxHashAndEventIndex,
            address_format: AddressFormat::Eip55,
        };
        let event_instantiated =
            cosmwasm_std::Event::new("instantiated").add_attributes(<Vec<Attribute>>::from(config));

        let event_messages_poll_started: cosmwasm_std::Event = PollStarted::Messages {
            messages: vec![
                TxEventConfirmation {
                    tx_id: "txId1".try_into().unwrap(),
                    event_index: 1,
                    message_id: "messageId".try_into().unwrap(),
                    destination_address: "destinationAddress1".parse().unwrap(),
                    destination_chain: "destinationChain".try_into().unwrap(),
                    source_address: "sourceAddress1".parse().unwrap(),
                    payload_hash: [0; 32],
                },
                TxEventConfirmation {
                    tx_id: "txId2".try_into().unwrap(),
                    event_index: 2,
                    message_id: "messageId".try_into().unwrap(),
                    destination_address: "destinationAddress2".parse().unwrap(),
                    destination_chain: "destinationChain".try_into().unwrap(),
                    source_address: "sourceAddress2".parse().unwrap(),
                    payload_hash: [1; 32],
                },
            ],
            metadata: PollMetadata {
                poll_id: 1.into(),
                source_chain: "sourceChain".try_into().unwrap(),
                source_gateway_address: "sourceGatewayAddress".try_into().unwrap(),
                confirmation_height: 1,
                expires_at: 1,
                participants: vec![
                    api.addr_make("participant1"),
                    api.addr_make("participant2"),
                    api.addr_make("participant3"),
                ],
            },
        }
        .into();

        let event_verifier_set_poll_started: cosmwasm_std::Event = PollStarted::VerifierSet {
            verifier_set: VerifierSetConfirmation {
                tx_id: "txId".try_into().unwrap(),
                event_index: 1,
                message_id: "messageId".try_into().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
            metadata: PollMetadata {
                poll_id: 2.into(),
                source_chain: "sourceChain".try_into().unwrap(),
                source_gateway_address: "sourceGatewayAddress".try_into().unwrap(),
                confirmation_height: 1,
                expires_at: 1,
                participants: vec![
                    api.addr_make("participant4"),
                    api.addr_make("participant5"),
                    api.addr_make("participant6"),
                ],
            },
        }
        .into();

        let event_quorum_reached: cosmwasm_std::Event = QuorumReached {
            content: "content".to_string(),
            status: VerificationStatus::NotFoundOnSourceChain,
            poll_id: 1.into(),
        }
        .into();

        let event_voted: cosmwasm_std::Event = Voted {
            poll_id: 1.into(),
            voter: api.addr_make("voter"),
            votes: vec![Vote::SucceededOnChain, Vote::FailedOnChain, Vote::NotFound],
        }
        .into();

        let event_poll_ended: cosmwasm_std::Event = PollEnded {
            poll_id: 1.into(),
            source_chain: "sourceChain".try_into().unwrap(),
            results: vec![
                Some(Vote::SucceededOnChain),
                Some(Vote::FailedOnChain),
                Some(Vote::NotFound),
                None,
            ],
        }
        .into();

        goldie::assert_json!(json!({
            "event_instantiated": event_instantiated,
            "event_messages_poll_started": event_messages_poll_started,
            "event_verifier_set_poll_started": event_verifier_set_poll_started,
            "event_quorum_reached": event_quorum_reached,
            "event_voted": event_voted,
            "event_poll_ended": event_poll_ended,
        }));
    }
}
