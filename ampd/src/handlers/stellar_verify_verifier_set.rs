use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::Event;
use events_derive::try_from;
use multisig::verifier_set::VerifierSet;
use prost_types::Any;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use stellar_xdr::curr::ScAddress;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::stellar::http_client::Client;
use crate::stellar::verifier::verify_verifier_set;
use crate::types::TMAddress;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub tx_id: String,
    pub event_index: u32,
    pub verifier_set: VerifierSet,
}

#[serde_as]
#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    #[serde_as(as = "DisplayFromStr")]
    source_gateway_address: ScAddress,
    verifier_set: VerifierSetConfirmation,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler {
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    http_client: Client,
    latest_block_height: Receiver<u64>,
}

impl Handler {
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        http_client: Client,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            http_client,
            latest_block_height,
        }
    }

    fn vote_msg(&self, poll_id: PollId, votes: Vec<Vote>) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.voting_verifier_contract.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
                .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    type Err = Error;

    async fn handle(&self, event: &Event) -> error_stack::Result<Vec<Any>, Self::Err> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_gateway_address,
            verifier_set,
            expires_at,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
        };

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        if *self.latest_block_height.borrow() >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let transaction_response = self
            .http_client
            .transaction_response(verifier_set.tx_id.clone())
            .await
            .change_context(Error::TxReceipts)?;

        let vote = info_span!(
            "verify a new verifier set",
            poll_id = poll_id.to_string(),
            id = format!("{}-{}", verifier_set.tx_id, verifier_set.event_index),
        )
        .in_scope(|| {
            info!("ready to verify verifier set in poll",);

            let vote = transaction_response.map_or(Vote::NotFound, |tx_receipt| {
                verify_verifier_set(&source_gateway_address, &tx_receipt, &verifier_set)
            });

            info!(
                vote = vote.as_value(),
                "ready to vote for a new verifier set in poll"
            );

            vote
        });

        Ok(vec![self
            .vote_msg(poll_id, vec![vote])
            .into_any()
            .expect("vote msg should serialize")])
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use error_stack::Result;
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ed25519_test_data};
    use stellar_xdr::curr::ScAddress;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::stellar::http_client::Client;
    use crate::types::{Hash, TMAddress};
    use crate::PREFIX;

    #[test]
    fn should_not_deserialize_incorrect_event() {
        // incorrect event type
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut event_type, ..
            } => {
                *event_type = "incorrect".into();
            }
            _ => panic!("incorrect event type"),
        }
        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            EventTypeMismatch(_)
        ));

        // invalid field
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut attributes, ..
            } => {
                attributes.insert("source_gateway_address".into(), "invalid".into());
            }
            _ => panic!("incorrect event type"),
        }

        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: Result<PollStartedEvent, events::Error> = event.try_into();
        assert!(event.is_ok());
    }

    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            Client::faux(),
            watch::channel(0).1,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn verifier_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            voting_verifier,
            Client::faux(),
            watch::channel(0).1,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_vote_correctly() {
        let mut client = Client::faux();
        faux::when!(client.transaction_response).then(|_| Ok(None));

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(verifier, voting_verifier, client, watch::channel(0).1);

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "stellar".parse().unwrap(),
                source_gateway_address: ScAddress::Contract(stellar_xdr::curr::Hash::from(
                    Hash::random().0,
                ))
                .to_string()
                .try_into()
                .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            verifier_set: VerifierSetConfirmation {
                tx_id: format!("{:x}", Hash::random()).parse().unwrap(),
                event_index: 0,
                verifier_set: build_verifier_set(KeyType::Ed25519, &ed25519_test_data::signers()),
            },
        }
    }
}
