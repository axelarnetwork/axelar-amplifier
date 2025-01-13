use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::Event;
use events_derive::try_from;
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::stacks::http_client::Client;
use crate::stacks::verifier::verify_verifier_set;
use crate::types::TMAddress;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub message_id: HexTxHashAndEventIndex,
    pub verifier_set: VerifierSet,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_gateway_address: String,
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

    async fn handle(&self, event: &Event) -> error_stack::Result<Vec<Any>, Error> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_gateway_address,
            verifier_set,
            participants,
            expires_at,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![]);
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let transaction = self
            .http_client
            .get_valid_transaction(&verifier_set.message_id.tx_hash.into())
            .await;

        let vote = info_span!(
            "verify a new verifier set for Stacks",
            poll_id = poll_id.to_string(),
            id = verifier_set.message_id.to_string(),
        )
        .in_scope(|| {
            info!("ready to verify a new worker set in poll");

            let vote = transaction.map_or(Vote::NotFound, |transaction| {
                verify_verifier_set(&source_gateway_address, &transaction, verifier_set)
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
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use assert_ok::assert_ok;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use cosmwasm_std;
    use cosmwasm_std::{HexBinary, Uint128};
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::into_structured_event;
    use crate::stacks::http_client::Client;
    use crate::types::{Hash, TMAddress};
    use crate::PREFIX;

    #[test]
    fn should_deserialize_verifier_set_poll_started_event() {
        let event: PollStartedEvent = assert_ok!(into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into());

        goldie::assert_debug!(&event);

        assert!(event.poll_id == 100u64.into());
        assert!(
            event.source_gateway_address
                == "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway"
        );

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

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            Client::faux(),
            watch::channel(0).1,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
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
            verifier_set_poll_started_event(participants(5, None), 100),
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
    async fn should_skip_expired_poll() {
        let mut client = Client::faux();
        faux::when!(client.get_valid_transaction).then(|_| None);

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

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier, client, rx);

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
        faux::when!(client.get_valid_transaction).then(|_| None);

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(worker, voting_verifier, client, watch::channel(0).1);

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let msg_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "multiversx".parse().unwrap(),
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
            #[allow(deprecated)] // TODO: The below events use the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                tx_id: msg_id.tx_hash_as_hex(),
                event_index: u32::try_from(msg_id.event_index).unwrap(),
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
        }
    }

    fn participants(n: u8, worker: Option<TMAddress>) -> Vec<TMAddress> {
        (0..n)
            .map(|_| TMAddress::random(PREFIX))
            .chain(worker)
            .collect()
    }
}
