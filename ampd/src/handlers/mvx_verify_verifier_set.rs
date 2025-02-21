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
use multiversx_sdk::data::address::Address;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::mvx::proxy::MvxProxy;
use crate::mvx::verifier::verify_verifier_set;
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
    source_gateway_address: Address,
    verifier_set: VerifierSetConfirmation,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler<P>
where
    P: MvxProxy + Send + Sync,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    blockchain: P,
    latest_block_height: Receiver<u64>,
}

impl<P> Handler<P>
where
    P: MvxProxy + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        blockchain: P,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            blockchain,
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
impl<P> EventHandler for Handler<P>
where
    P: MvxProxy + Send + Sync,
{
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

        let transaction_info = self
            .blockchain
            .transaction_info_with_results(&verifier_set.message_id.tx_hash.into())
            .await;

        let vote = info_span!(
            "verify a new verifier set for MultiversX",
            poll_id = poll_id.to_string(),
            id = verifier_set.message_id.to_string(),
        )
        .in_scope(|| {
            info!("ready to verify a new worker set in poll");

            let vote = transaction_info.map_or(Vote::NotFound, |transaction| {
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
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use cosmwasm_std;
    use cosmwasm_std::Uint128;
    use events::Event;
    use hex::ToHex;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ed25519_test_data};
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::mvx::proxy::MockMvxProxy;
    use crate::types::TMAddress;
    use crate::PREFIX;

    #[test]
    fn mvx_verify_verifier_set_should_deserialize_correct_event() {
        let event: PollStartedEvent = assert_ok!(into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into());

        goldie::assert_debug!(&event);

        assert!(event.poll_id == 100u64.into());
        assert!(
            event.source_gateway_address.to_bech32_string().unwrap()
                == "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx"
        );

        let verifier_set = event.verifier_set;

        assert!(
            verifier_set.message_id.tx_hash.encode_hex::<String>()
                == "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312"
        );
        assert!(verifier_set.message_id.event_index == 1u64);
        assert!(verifier_set.verifier_set.signers.len() == 3);
        assert_eq!(verifier_set.verifier_set.threshold, Uint128::from(2u128));
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
            MockMvxProxy::new(),
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
            MockMvxProxy::new(),
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
            MockMvxProxy::new(),
            watch::channel(0).1,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut proxy = MockMvxProxy::new();
        proxy
            .expect_transaction_info_with_results()
            .returning(|_| None);

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            verifier_set_poll_started_event(
                vec![verifier.clone()].into_iter().collect(),
                expiration,
            ),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier, proxy, rx);

        // poll is not expired yet, should hit proxy
        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_vote_correctly() {
        let mut proxy = MockMvxProxy::new();
        proxy
            .expect_transaction_info_with_results()
            .returning(|_| None);

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(worker, voting_verifier, proxy, watch::channel(0).1);

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "multiversx".parse().unwrap(),
                source_gateway_address:
                    "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx"
                        .parse()
                        .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                tx_id: "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312"
                    .parse()
                    .unwrap(),
                event_index: 1,
                message_id: "0xdfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312-1"
                    .to_string()
                    .try_into()
                    .unwrap(),
                verifier_set: build_verifier_set(KeyType::Ed25519, &ed25519_test_data::signers()),
            },
        }
    }
}
