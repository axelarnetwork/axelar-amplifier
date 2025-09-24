use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use clarity_serialization::types::{PrincipalData, TypeSignature};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, Event, EventType};
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::event_sub::event_filter::{EventFilter, EventFilters};
use crate::handlers::errors::Error;
use crate::monitoring;
use crate::monitoring::metrics;
use crate::stacks::finalizer::latest_finalized_block_height;
use crate::stacks::http_client::Client;
use crate::stacks::verifier::{type_signature_signers_rotated, verify_verifier_set};
use crate::types::TMAddress;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub message_id: HexTxHashAndEventIndex,
    pub verifier_set: VerifierSet,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    #[serde(with = "crate::stacks::principal_data_serde")]
    source_gateway_address: PrincipalData,
    verifier_set: VerifierSetConfirmation,
    participants: Vec<TMAddress>,
    expires_at: u64,
    confirmation_height: u64,
}

pub struct Handler {
    chain_name: ChainName,
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    http_client: Client,
    latest_block_height: Receiver<u64>,
    type_signature_signers_rotated: TypeSignature,
    monitoring_client: monitoring::Client,
}

impl Handler {
    pub fn new(
        chain_name: ChainName,
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        http_client: Client,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> error_stack::Result<Self, crate::stacks::error::Error> {
        let type_signature_signers_rotated = type_signature_signers_rotated()?;

        Ok(Self {
            chain_name,
            verifier,
            voting_verifier_contract,
            http_client,
            latest_block_height,
            type_signature_signers_rotated,
            monitoring_client,
        })
    }

    fn vote_msg(&self, poll_id: PollId, vote: Vote) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.voting_verifier_contract.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote {
                poll_id,
                votes: vec![vote],
            })
            .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            verifier_set,
            participants,
            expires_at,
            confirmation_height,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![]);
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if source_chain != self.chain_name {
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let latest_finalized_block_height =
            latest_finalized_block_height(&self.http_client, confirmation_height)
                .await
                .change_context(Error::Finalizer)?;

        let transaction = self
            .http_client
            .valid_transaction(
                &verifier_set.message_id.tx_hash.into(),
                latest_finalized_block_height,
            )
            .await;

        let vote = info_span!(
            "verify a new verifier set for Stacks",
            poll_id = poll_id.to_string(),
            id = verifier_set.message_id.to_string(),
        )
        .in_scope(|| {
            info!("ready to verify a new worker set in poll");

            let vote = transaction.map_or(Vote::NotFound, |transaction| {
                verify_verifier_set(
                    &source_gateway_address,
                    &transaction,
                    verifier_set,
                    &self.type_signature_signers_rotated,
                )
            });

            self.monitoring_client
                .metrics()
                .record_metric(metrics::Msg::VerificationVote {
                    vote_decision: vote.clone(),
                    chain_name: self.chain_name.clone(),
                });
            info!(
                vote = vote.as_value(),
                "ready to vote for a new worker set in poll"
            );

            vote
        });

        Ok(vec![self
            .vote_msg(poll_id, vote)
            .into_any()
            .expect("vote msg should serialize")])
    }

    fn event_filters(&self) -> EventFilters {
        EventFilters::new(
            vec![EventFilter::EventTypeAndContract(
                PollStartedEvent::event_type(),
                self.voting_verifier_contract.clone(),
            )],
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use assert_ok::assert_ok;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use cosmwasm_std;
    use cosmwasm_std::{HexBinary, Uint128};
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use router_api::chain_name;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use super::{Handler, PollStartedEvent};
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::monitoring::{metrics, test_utils};
    use crate::stacks::http_client::{Block, Client};
    use crate::types::{Hash, TMAddress};
    use crate::PREFIX;

    const STACKS: &str = "stacks";

    #[test]
    fn stacks_should_deserialize_verifier_set_poll_started_event() {
        let event: PollStartedEvent = assert_ok!(into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into());

        goldie::assert_debug!(&event);

        assert!(event.poll_id == 100u64.into());
        assert!(
            event.source_gateway_address.to_string()
                == "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway"
        );
        assert!(event.confirmation_height == 15);

        let verifier_set = event.verifier_set;

        assert!(verifier_set.message_id.event_index == 1u64);
        assert!(verifier_set.verifier_set.signers.len() == 3);
        assert_eq!(verifier_set.verifier_set.threshold, Uint128::from(2u128));

        let mut signers = verifier_set.verifier_set.signers.values();
        let signer1 = signers.next().unwrap();
        let signer2 = signers.next().unwrap();

        assert_eq!(
            signer1.pub_key.as_ref(),
            HexBinary::from_hex(
                "02d530fb1b8fcfb978c37d8d74d4a79ca840a01df457e48a81bbe01bc962820921",
            )
            .unwrap()
            .as_ref()
        );
        assert_eq!(signer1.weight, Uint128::from(1u128));

        assert_eq!(
            signer2.pub_key.as_ref(),
            HexBinary::from_hex(
                "0354f1838e4dbc30d4c612633b9dc54c06ead9723bb164afee0bcc516cbb156985",
            )
            .unwrap()
            .as_ref()
        );
        assert_eq!(signer2.weight, Uint128::from(1u128));
    }

    #[async_test]
    async fn not_poll_started_event() {
        let event = into_structured_event(
            cosmwasm_std::Event::new("transfer"),
            &TMAddress::random(PREFIX),
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::new(
            chain_name!(STACKS),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            Client::faux(),
            watch::channel(0).1,
            monitoring_client,
        )
        .unwrap();

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::new(
            chain_name!(STACKS),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            Client::faux(),
            watch::channel(0).1,
            monitoring_client,
        )
        .unwrap();

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn incorrect_chain() {
        let client = Client::faux();

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (monitoring_client, _) = test_utils::monitoring_client();
        let event = into_structured_event(
            verifier_set_poll_started_event(
                vec![verifier.clone()].into_iter().collect(),
                expiration,
            ),
            &voting_verifier,
        );

        let handler = Handler::new(
            chain_name!("other"),
            verifier,
            voting_verifier,
            client,
            watch::channel(0).1,
            monitoring_client,
        )
        .unwrap();

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn verifier_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::new(
            chain_name!(STACKS),
            TMAddress::random(PREFIX),
            voting_verifier,
            Client::faux(),
            watch::channel(0).1,
            monitoring_client,
        )
        .unwrap();

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut client = Client::faux();
        faux::when!(client.latest_block).then(|_| {
            Ok(Block {
                burn_block_height: 1,
            })
        });
        faux::when!(client.valid_transaction).then(|_| None);

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            verifier_set_poll_started_event(
                vec![verifier.clone()].into_iter().collect(),
                expiration,
            ),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = Handler::new(
            chain_name!(STACKS),
            verifier,
            voting_verifier,
            client,
            rx,
            monitoring_client,
        )
        .unwrap();

        // poll is not expired yet, should hit proxy
        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_vote_correctly() {
        let mut client = Client::faux();
        faux::when!(client.latest_block).then(|_| {
            Ok(Block {
                burn_block_height: 1,
            })
        });
        faux::when!(client.valid_transaction).then(|_| None);

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::new(
            chain_name!(STACKS),
            worker,
            voting_verifier,
            client,
            watch::channel(0).1,
            monitoring_client,
        )
        .unwrap();

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_record_verification_vote_metric() {
        let mut client = Client::faux();
        faux::when!(client.latest_block).then(|_| {
            Ok(Block {
                burn_block_height: 1,
            })
        });
        faux::when!(client.valid_transaction).then(|_| None);

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = Handler::new(
            chain_name!(STACKS),
            worker,
            voting_verifier,
            client,
            watch::channel(0).1,
            monitoring_client,
        )
        .unwrap();

        let _ = handler.handle(&event).await.unwrap();

        let metric = receiver.recv().await.unwrap();
        assert_eq!(
            metric,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: handler.chain_name.clone(),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let msg_id = HexTxHashAndEventIndex::new(Hash::from([3; 32]), 1u64);

        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!(STACKS),
                source_gateway_address: "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway"
                    .parse()
                    .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            #[allow(
                deprecated
            )] // TODO: The below events use the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                tx_id: msg_id.tx_hash_as_hex(),
                event_index: u32::try_from(msg_id.event_index).unwrap(),
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
        }
    }
}
