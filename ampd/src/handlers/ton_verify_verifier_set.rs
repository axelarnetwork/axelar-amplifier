use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::try_from;
use events::Error::EventTypeMismatch;
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tonlib_core::TonAddress;
use tracing::{info, info_span};
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::ton::rpc::TonClient;
use crate::ton::verifier::verify_verifier_set;
use crate::types::TMAddress;

type Result<T> = error_stack::Result<T, Error>;

use crate::handlers::ton_verify_msg::hex_tx_hash_string;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    #[serde(with = "hex_tx_hash_string")]
    pub message_id: HexTxHash,
    pub verifier_set: VerifierSet,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: TonAddress,
    expires_at: u64,
    participants: Vec<TMAddress>,
}

pub struct Handler<C>
where
    C: TonClient,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C> Handler<C>
where
    C: TonClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            rpc_client,
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
impl<C> EventHandler for Handler<C>
where
    C: TonClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            expires_at,
            participants,
            verifier_set,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
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

        let vote = info_span!(
            "verify a new verifier set for an EVM chain",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            id = verifier_set.message_id.to_string()
        )
        .in_scope(|| async {
            info!("ready to verify a new verifier set in poll");

            let log = self
                .rpc_client
                .get_log(&source_gateway_address, &verifier_set.message_id)
                .await;
            if log.is_err() {
                return Vote::NotFound;
            }
            let log = log.unwrap();

            match verify_verifier_set(log, &verifier_set) {
                true => Vote::SucceededOnChain,
                false => Vote::FailedOnChain,
            }
        });

        Ok(vec![self
            .vote_msg(poll_id, vote.await)
            .into_any()
            .expect("vote msg should serialize")])
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    use axelar_wasm_std::msg_id::HexTxHash;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmwasm_std;
    use error_stack::Result;
    use ethers_core::types::H256;
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ed25519_test_data};
    use serde_json::Value;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use ton_utils::WeightedSigners;
    use tonlib_core::TonAddress;
    use voting_verifier::events::{PollMetadata, PollStarted};

    use super::*;
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::handlers::ton_verify_msg::FetchingError;
    use crate::handlers::ton_verify_verifier_set::PollStartedEvent;
    use crate::ton::rpc::{TonClient, TonLog, TonRpcClient};
    use crate::ton::verifier::OP_SIGNERS_ROTATED;
    use crate::types::TMAddress;
    use crate::PREFIX;

    #[test]
    fn ton_verify_verifier_set_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100, 1),
            &TMAddress::random(PREFIX),
        );
        let event: Result<PollStartedEvent, _> = event.try_into();

        assert!(event.is_ok());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let rpc_client = TonRpcClient::new("invalid");

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration, 1),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier, rpc_client, rx);

        // poll is not expired yet, should get one no vote
        let result = handler.handle(&event).await.unwrap();
        assert_eq!(result.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired, should not get a vote
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    fn poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
        msg_id: u8,
    ) -> PollStarted {
        let msg_id = HexTxHash::new(H256::repeat_byte(msg_id));
        PollStarted::VerifierSet {
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: voting_verifier::events::VerifierSetConfirmation {
                tx_id: msg_id.tx_hash_as_hex_no_prefix(),
                event_index: 0u32,
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_ton_verifier_set(),
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "ethereum".parse().unwrap(),
                source_gateway_address: "kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH"
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

    #[test]
    fn should_not_deserialize_incorrect_event() {
        // incorrect event type
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100, 1),
            &TMAddress::random(PREFIX),
        );

        assert!(matches!(event, Event::Abci { .. }));
        match event {
            Event::Abci {
                ref mut event_type, ..
            } => {
                *event_type = "incorrect".into();
            }
            _ => unreachable!("Variant already checked"),
        }
        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            EventTypeMismatch(_)
        ));

        // invalid field
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100, 1),
            &TMAddress::random(PREFIX),
        );

        assert!(matches!(event, Event::Abci { .. }));
        match event {
            Event::Abci {
                ref mut attributes, ..
            } => {
                attributes.insert("source_gateway_address".into(), "invalid".into());
            }
            _ => unreachable!("Variant already checked"),
        }

        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn ton_verify_verifier_set_should_deserialize_correct_event_check() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100, 1),
            &TMAddress::random(PREFIX),
        );

        let event: PollStartedEvent = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn ton_verify_verifier_set_should_skip_expired_poll() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration, 1),
            &voting_verifier_contract,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        // poll is not expired yet, should get one vote
        let vote = handler.handle(&event).await.unwrap();
        assert_eq!(vote.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired, should not get a vote
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn ton_verify_verifier_set_should_skip_not_poll_started_event() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            cosmwasm_std::Event::new("transfer"), // not a poll started event
            &voting_verifier_contract,
        );

        let (_tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn ton_verify_verifier_set_should_skip_poll_not_from_voting_verifier() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let other_contract = TMAddress::random(PREFIX);

        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100, 1),
            &other_contract,
        );

        let (_tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn ton_verify_verifier_set_should_skip_poll_when_verifier_is_not_participant() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let voting_verifier_contract = TMAddress::random(PREFIX);

        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, None), 100, 1),
            &voting_verifier_contract,
        );

        let (_tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    async fn simulate_vote(rpc_client: impl TonClient, msg_id: u8) -> Value {
        let voting_verifier_contract = TMAddress::random(PREFIX);

        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100, msg_id),
            &voting_verifier_contract,
        );

        let (_tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        let msg_execute_contract = MsgExecuteContract::from_any(actual.first().unwrap()).unwrap();

        let json_str = String::from_utf8(msg_execute_contract.msg).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        parsed
    }

    #[async_test]
    async fn ton_verify_verifier_set_should_vote_yes_on_correct_set() {
        let rpc_client = ValidResponseTonRpc;

        let result = simulate_vote(rpc_client, 1).await;

        goldie::assert_json!(result);
    }

    #[async_test]
    async fn ton_verify_verifier_set_should_vote_no_on_incorrect_set() {
        let rpc_client = ValidResponseTonRpc;

        let result = simulate_vote(rpc_client, 2).await;

        goldie::assert_json!(result);
    }

    #[async_test]
    async fn ton_verify_verifier_set_should_vote_no_when_not_found() {
        let rpc_client = ValidResponseTonRpc;

        let result = simulate_vote(rpc_client, 3).await;

        goldie::assert_json!(result);
    }

    #[async_test]
    async fn ton_verify_verifier_set_should_vote_no_on_rpc_failure() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let result = simulate_vote(rpc_client, 1).await;

        goldie::assert_json!(result);
    }

    fn build_ton_verifier_set() -> VerifierSet {
        let mut verifier_set = build_verifier_set(KeyType::Ed25519, &ed25519_test_data::signers());

        // remap the keys to numeric values
        let remapped_signers: BTreeMap<String, _> = verifier_set
            .signers
            .values()
            .cloned()
            .enumerate()
            .map(|(key, value)| (key.to_string(), value))
            .collect();
        verifier_set.signers = remapped_signers;
        verifier_set
    }

    struct ValidResponseTonRpc;
    #[async_trait::async_trait]
    impl TonClient for ValidResponseTonRpc {
        async fn get_log(
            &self,
            _contract_address: &TonAddress,
            tx_hash: &HexTxHash,
        ) -> error_stack::Result<TonLog, FetchingError> {
            let msg_id1 = HexTxHash::new(H256::repeat_byte(1));
            let msg_id2 = HexTxHash::new(H256::repeat_byte(2));

            let mut incorrect_verifier_set = build_ton_verifier_set();
            incorrect_verifier_set.signers.remove("1");

            let msgs = vec![
                // This correct message matches the first TxEventConfirmation in the simulated event
                // The vote for the first message should thus be SucceededOnChain
                VerifierSetConfirmation {
                    message_id: msg_id1.to_string().parse().unwrap(),
                    verifier_set: build_ton_verifier_set(),
                },
                // This message has the same cc_id as the second TxEventConfirmation, but differs
                // in the destination address. The vote for the second message should thus be FailedOnChain
                VerifierSetConfirmation {
                    message_id: msg_id2.to_string().parse().unwrap(),
                    verifier_set: incorrect_verifier_set,
                },
            ];

            let queried_msg = msgs.into_iter().find(|msg| *tx_hash == msg.message_id);
            match queried_msg {
                Some(msg) => {
                    let weighted_signers: WeightedSigners =
                        WeightedSigners::try_from(msg.verifier_set).unwrap();
                    let cell = weighted_signers.to_cell().unwrap().to_arc();

                    Ok(TonLog {
                        opcode: OP_SIGNERS_ROTATED,
                        cell,
                    })
                }
                None => Err(FetchingError::NotFound)?,
            }
        }
    }
}
