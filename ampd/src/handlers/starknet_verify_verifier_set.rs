//! Module responsible for handling verification of verifier set changes.
//! It processes events related to verifier set, verifies them against the Starknet chain,
//! and manages the voting process for confirming these changes.

use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::FieldElementAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, Event};
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::handlers::record_metrics::*;
use crate::monitoring;
use crate::starknet::json_rpc::StarknetClient;
use crate::starknet::verifier::verify_verifier_set;
use crate::types::TMAddress;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub message_id: FieldElementAndEventIndex,
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

#[derive(Debug)]
pub struct Handler<C>
where
    C: StarknetClient + Send + Sync,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<C> Handler<C>
where
    C: StarknetClient + Send + Sync,
{
    /// Handler for verifying verifier set updates from Starknet
    ///
    /// # Type Parameters
    /// * `C` - A Starknet client type that implements the [`StarknetClient`] trait
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            rpc_client,
            latest_block_height,
            monitoring_client,
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
impl<C> EventHandler for Handler<C>
where
    C: StarknetClient + Send + Sync + 'static,
{
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
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        if *self.latest_block_height.borrow() >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let transaction_response = self
            .rpc_client
            .event_by_message_id_signers_rotated(verifier_set.message_id.clone())
            .await;

        let handler_chain_name = "starknet";

        let vote = info_span!(
            "verify a new verifier set",
            poll_id = poll_id.to_string(),
            message_id = verifier_set.message_id.to_string(),
        )
        .in_scope(|| {
            info!("ready to verify verifier set in poll",);

            let vote = match transaction_response {
                None => Vote::NotFound,
                Some(tx_receipt) => {
                    verify_verifier_set(&tx_receipt, &verifier_set, &source_gateway_address)
                }
            };

            record_vote_verification_metric(&self.monitoring_client, &vote, handler_chain_name);

            info!(
                vote = vote.as_value(),
                "ready to vote for a new verifier set in poll"
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
    use std::net::SocketAddr;
    use std::str::FromStr;

    use axelar_wasm_std::msg_id::FieldElementAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use error_stack::Result;
    use ethers_core::types::U256;
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use rand::Rng;
    use starknet_checked_felt::CheckedFelt;
    use tendermint::abci;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use crate::event_processor::EventHandler;
    use crate::handlers::starknet_verify_verifier_set::PollStartedEvent;
    use crate::monitoring::metrics::Msg as MetricsMsg;
    use crate::monitoring::test_utils::create_test_monitoring_client;
    use crate::starknet::json_rpc::MockStarknetClient;
    use crate::types::TMAddress;
    use crate::{monitoring, PREFIX};

    #[test]
    fn should_deserialize_correct_event() {
        let event: Event = to_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: Result<PollStartedEvent, events::Error> = event.try_into();

        assert!(event.is_ok());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut rpc_client = MockStarknetClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client
            .expect_event_by_message_id_signers_rotated()
            .returning(|_| None);

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = to_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_send_correct_vote_verification_messages() {
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);

        let mut rpc_client = MockStarknetClient::new();
        rpc_client
            .expect_get_event_by_message_id_signers_rotated()
            .returning(|_| None);

        let event: Event = to_event(
            poll_started_event(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = create_test_monitoring_client();

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );
        let _ = handler.handle(&event).await.unwrap();

        assert_eq!(
            receiver.try_recv().unwrap(),
            MetricsMsg::VoteVerification {
                vote_status: Vote::NotFound,
                chain_name: "starknet".to_string(),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    fn random_hash() -> String {
        // Generate a random 256-bit value
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32]; // Allocate a fixed-size array of 32 bytes
        rng.fill(&mut bytes); // Fill the array with random bytes

        let number = U256::from_big_endian(&bytes);

        let max_felt_in_bytes: [u8; 32] = [
            8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let max: U256 = U256::from_big_endian(&max_felt_in_bytes);

        let result = number.checked_rem(max).expect("modulo operation failed");

        format!("0x{:064x}", result)
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let random_felt = CheckedFelt::from_str(&random_hash()).unwrap();
        let msg_id = FieldElementAndEventIndex::new(random_felt, 100u64).unwrap();
        PollStarted::VerifierSet {
            #[allow(deprecated)]
            verifier_set: VerifierSetConfirmation {
                tx_id: msg_id.tx_hash_as_hex(),
                event_index: u32::try_from(msg_id.event_index).unwrap(),
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "starknet-devnet-v1".parse().unwrap(),
                source_gateway_address:
                    "0x049ec69cd2e0c987857fbda7966ff59077e2e92c18959bdb9b0012438c452047"
                        .parse()
                        .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
        }
    }

    fn to_event(event: impl Into<cosmwasm_std::Event>, contract_address: &TMAddress) -> Event {
        let mut event: cosmwasm_std::Event = event.into();

        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute("_contract_address", contract_address.to_string());

        abci::Event::new(
            event.ty,
            event
                .attributes
                .into_iter()
                .map(|cosmwasm_std::Attribute { key, value }| {
                    (STANDARD.encode(key), STANDARD.encode(value))
                }),
        )
        .try_into()
        .unwrap()
    }

    fn participants(n: u8, verifier: Option<TMAddress>) -> Vec<TMAddress> {
        (0..n)
            .map(|_| TMAddress::random(PREFIX))
            .chain(verifier)
            .collect()
    }
}
