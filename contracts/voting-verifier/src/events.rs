use std::str::FromStr;
use std::vec::Vec;

use axelar_wasm_std::msg_id::base_58_event_index::Base58TxDigestAndEventIndex;
use axelar_wasm_std::msg_id::base_58_solana_event_index::Base58SolanaTxDigestAndEventIndex;
use axelar_wasm_std::msg_id::tx_hash_event_index::HexTxHashAndEventIndex;
use axelar_wasm_std::msg_id::MessageIdFormat;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Attribute, Event};

use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, VerificationStatus};
use multisig::verifier_set::VerifierSet;
use router_api::{Address, ChainName, Message};

use crate::error::ContractError;
use crate::state::Config;

impl From<Config> for Vec<Attribute> {
    fn from(other: Config) -> Self {
        vec![
            ("service_name", other.service_name.to_string()),
            (
                "service_registry_contract",
                other.service_registry_contract.to_string(),
            ),
            (
                "source_gateway_address",
                other.source_gateway_address.to_string(),
            ),
            (
                "voting_threshold",
                serde_json::to_string(&other.voting_threshold)
                    .expect("failed to serialize voting_threshold"),
            ),
            ("block_expiry", other.block_expiry.to_string()),
            ("confirmation_height", other.confirmation_height.to_string()),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect()
    }
}

pub struct PollMetadata {
    pub poll_id: PollId,
    pub source_chain: ChainName,
    pub source_gateway_address: nonempty::String,
    pub confirmation_height: u64,
    pub expires_at: u64,
    pub participants: Vec<Addr>,
}

pub enum PollStarted {
    Messages {
        messages: Vec<TxEventConfirmation>,
        metadata: PollMetadata,
    },
    VerifierSet {
        verifier_set: VerifierSetConfirmation,
        metadata: PollMetadata,
    },
}

impl From<PollMetadata> for Vec<Attribute> {
    fn from(value: PollMetadata) -> Self {
        vec![
            (
                "poll_id",
                &serde_json::to_string(&value.poll_id).expect("failed to serialize poll_id"),
            ),
            ("source_chain", &value.source_chain.to_string()),
            ("source_gateway_address", &value.source_gateway_address),
            (
                "confirmation_height",
                &value.confirmation_height.to_string(),
            ),
            ("expires_at", &value.expires_at.to_string()),
            (
                "participants",
                &serde_json::to_string(&value.participants)
                    .expect("failed to serialize participants"),
            ),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect()
    }
}

impl From<PollStarted> for Event {
    fn from(other: PollStarted) -> Self {
        match other {
            PollStarted::Messages {
                messages: data,
                metadata,
            } => Event::new("messages_poll_started")
                .add_attribute(
                    "messages",
                    serde_json::to_string(&data).expect("failed to serialize messages"),
                )
                .add_attributes(Vec::<_>::from(metadata)),
            PollStarted::VerifierSet {
                verifier_set: data,
                metadata,
            } => Event::new("verifier_set_poll_started")
                .add_attribute(
                    "verifier_set",
                    serde_json::to_string(&data)
                        .expect("failed to serialize verifier set confirmation"),
                )
                .add_attributes(Vec::<_>::from(metadata)),
        }
    }
}

#[cw_serde]
pub struct VerifierSetConfirmation {
    pub tx_id: nonempty::String,
    pub event_index: u32,
    pub verifier_set: VerifierSet,
}

/// If parsing is successful, returns (tx_id, event_index). Otherwise returns ContractError::InvalidMessageID
fn parse_message_id(
    message_id: nonempty::String,
    msg_id_format: &MessageIdFormat,
) -> Result<(nonempty::String, u32), ContractError> {
    match msg_id_format {
        MessageIdFormat::Base58TxDigestAndEventIndex => {
            let id = Base58TxDigestAndEventIndex::from_str(&message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.into()))?;
            Ok((id.tx_digest_as_base58(), id.event_index))
        }
        MessageIdFormat::HexTxHashAndEventIndex => {
            let id = HexTxHashAndEventIndex::from_str(&message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.into()))?;

            Ok((id.tx_hash_as_hex(), id.event_index))
        }
        MessageIdFormat::Base58SolanaTxDigestAndEventIndex => {
            let id = Base58SolanaTxDigestAndEventIndex::from_str(&message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.into()))?;

            Ok((id.tx_digest_as_base58(), id.event_index))
        }
    }
}

impl VerifierSetConfirmation {
    pub fn new(
        message_id: nonempty::String,
        msg_id_format: MessageIdFormat,
        verifier_set: VerifierSet,
    ) -> Result<Self, ContractError> {
        let (tx_id, event_index) = parse_message_id(message_id, &msg_id_format)?;

        Ok(Self {
            tx_id,
            event_index,
            verifier_set,
        })
    }
}

#[cw_serde]
pub struct TxEventConfirmation {
    pub tx_id: nonempty::String,
    pub event_index: u32,
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
        let (tx_id, event_index) = parse_message_id(msg.cc_id.id, msg_id_format)?;

        Ok(TxEventConfirmation {
            tx_id,
            event_index,
            destination_address: msg.destination_address,
            destination_chain: msg.destination_chain,
            source_address: msg.source_address,
            payload_hash: msg.payload_hash,
        })
    }
}

pub struct Voted {
    pub poll_id: PollId,
    pub voter: Addr,
}

impl From<Voted> for Event {
    fn from(other: Voted) -> Self {
        Event::new("voted")
            .add_attribute(
                "poll_id",
                serde_json::to_string(&other.poll_id).expect("failed to serialize poll_id"),
            )
            .add_attribute("voter", other.voter)
    }
}

pub struct PollEnded {
    pub poll_id: PollId,
    pub results: Vec<Option<Vote>>,
}

impl From<PollEnded> for Event {
    fn from(other: PollEnded) -> Self {
        Event::new("poll_ended")
            .add_attribute(
                "poll_id",
                serde_json::to_string(&other.poll_id).expect("failed to serialize poll_id"),
            )
            .add_attribute(
                "results",
                serde_json::to_string(&other.results).expect("failed to serialize results"),
            )
    }
}

pub struct QuorumReached<T> {
    pub content: T,
    pub status: VerificationStatus,
}

impl<T> From<QuorumReached<T>> for Event
where
    T: cosmwasm_schema::serde::Serialize,
{
    fn from(value: QuorumReached<T>) -> Self {
        Event::new("quorum_reached")
            .add_attribute(
                "content",
                serde_json::to_string(&value.content).expect("failed to serialize content"),
            )
            .add_attribute(
                "status",
                serde_json::to_string(&value.status).expect("failed to serialize status"),
            )
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use axelar_wasm_std::{
        msg_id::{
            base_58_event_index::Base58TxDigestAndEventIndex,
            tx_hash_event_index::HexTxHashAndEventIndex, MessageIdFormat,
        },
        nonempty,
    };
    use cosmwasm_std::Uint128;
    use multisig::verifier_set::VerifierSet;
    use router_api::{CrossChainId, Message};

    use super::{TxEventConfirmation, VerifierSetConfirmation};

    fn random_32_bytes() -> [u8; 32] {
        let mut bytes = [0; 32];
        for b in &mut bytes {
            *b = rand::random();
        }
        bytes
    }

    fn generate_msg(msg_id: nonempty::String) -> Message {
        Message {
            cc_id: CrossChainId {
                chain: "source-chain".parse().unwrap(),
                id: msg_id,
            },
            source_address: "source_address".parse().unwrap(),
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
    fn should_make_tx_event_confirmation_with_hex_msg_id() {
        let msg_id = HexTxHashAndEventIndex {
            tx_hash: random_32_bytes(),
            event_index: 0,
        };
        let msg = generate_msg(msg_id.to_string().parse().unwrap());

        let event =
            TxEventConfirmation::try_from((msg.clone(), &MessageIdFormat::HexTxHashAndEventIndex))
                .unwrap();

        assert_eq!(event.tx_id, msg_id.tx_hash_as_hex());
        assert_eq!(event.event_index, msg_id.event_index);
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

        assert_eq!(event.tx_id, msg_id.tx_digest_as_base58());
        assert_eq!(event.event_index, msg_id.event_index);
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
            event_index: rand::random::<u32>(),
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

        assert_eq!(event.tx_id, msg_id.tx_hash_as_hex());
        assert_eq!(event.event_index, msg_id.event_index);
        assert_eq!(event.verifier_set, verifier_set);
    }

    #[test]
    fn should_make_verifier_set_confirmation_with_base58_msg_id() {
        let msg_id = Base58TxDigestAndEventIndex {
            tx_digest: random_32_bytes(),
            event_index: rand::random::<u32>(),
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

        assert_eq!(event.tx_id, msg_id.tx_digest_as_base58());
        assert_eq!(event.event_index, msg_id.event_index);
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
            event_index: rand::random::<u32>(),
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
}
