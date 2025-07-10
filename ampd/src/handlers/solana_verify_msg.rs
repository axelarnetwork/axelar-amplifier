use std::collections::HashMap;
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::try_from;
use events::Error::EventTypeMismatch;
use router_api::ChainName;
use serde::Deserialize;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiTransactionStatusMeta;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::solana::msg_verifier::verify_message;
use crate::solana::SolanaRpcClientProxy;
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub message_id: Base58SolanaTxSignatureAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    #[serde(deserialize_with = "crate::solana::deserialize_pubkey")]
    pub source_address: Pubkey,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

pub struct Handler<C: SolanaRpcClientProxy> {
    chain_name: ChainName,
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C: SolanaRpcClientProxy> Handler<C> {
    pub fn new(
        chain_name: ChainName,
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            chain_name,
            verifier,
            voting_verifier_contract,
            rpc_client,
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

    async fn fetch_message(
        &self,
        msg: &Message,
    ) -> Option<(solana_sdk::signature::Signature, UiTransactionStatusMeta)> {
        let signature = solana_sdk::signature::Signature::from(msg.message_id.raw_signature);
        self.rpc_client
            .get_tx(&signature)
            .await
            .map(|tx| (signature, tx))
    }
}

#[async_trait]
impl<C: SolanaRpcClientProxy> EventHandler for Handler<C> {
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            messages,
            expires_at,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
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

        let tx_calls = messages.iter().map(|msg| self.fetch_message(msg));
        let finalized_tx_receipts = futures::future::join_all(tx_calls)
            .await
            .into_iter()
            .flatten()
            .collect::<HashMap<_, _>>();

        let votes = info_span!(
            "verify messages from Solana",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            message_ids = messages
                .iter()
                .map(|msg| msg.message_id.to_string())
                .collect::<Vec<String>>()
                .as_value(),
        )
        .in_scope(|| {
            info!("ready to verify messages in poll",);

            let votes: Vec<_> = messages
                .iter()
                .map(|msg| {
                    finalized_tx_receipts
                        .get_key_value(&msg.message_id.raw_signature.into())
                        .map_or(Vote::NotFound, |entry| verify_message(entry, msg))
                })
                .collect();
            info!(
                votes = votes.as_value(),
                "ready to vote for messages in poll"
            );

            votes
        });

        Ok(vec![self
            .vote_msg(poll_id, votes)
            .into_any()
            .expect("vote msg should serialize")])
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use cosmrs::AccountId;
    use solana_sdk::signature::Signature;
    use solana_transaction_status::option_serializer::OptionSerializer;
    use tokio::sync::watch;
    use voting_verifier::events::{Event as VotingVerifierEvent, TxEventConfirmation};

    use super::*;
    use crate::handlers::tests::into_structured_event;
    use crate::types::TMAddress;
    use crate::PREFIX;

    struct EmptyResponseSolanaRpc;
    #[async_trait::async_trait]
    impl SolanaRpcClientProxy for EmptyResponseSolanaRpc {
        async fn get_tx(&self, _signature: &Signature) -> Option<UiTransactionStatusMeta> {
            None
        }

        async fn get_domain_separator(&self) -> Option<[u8; 32]> {
            unimplemented!()
        }
    }

    struct ValidResponseSolanaRpc;
    #[async_trait::async_trait]
    impl SolanaRpcClientProxy for ValidResponseSolanaRpc {
        async fn get_tx(&self, _signature: &Signature) -> Option<UiTransactionStatusMeta> {
            Some(UiTransactionStatusMeta {
                err: None,
                status: Ok(()),
                fee: 0,
                pre_balances: vec![],
                post_balances: vec![],
                inner_instructions: OptionSerializer::None,
                log_messages: OptionSerializer::None,
                pre_token_balances: OptionSerializer::None,
                post_token_balances: OptionSerializer::None,
                rewards: OptionSerializer::None,
                loaded_addresses: OptionSerializer::None,
                return_data: OptionSerializer::None,
                compute_units_consumed: OptionSerializer::None,
            })
        }

        async fn get_domain_separator(&self) -> Option<[u8; 32]> {
            unimplemented!()
        }
    }

    #[test]
    fn solana_verify_msg_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            poll_started_event(participants(None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(event);
    }

    // Should not handle event if it is not a poll started event
    #[tokio::test]
    async fn not_poll_started_event() {
        let event = into_structured_event(
            cosmwasm_std::Event::new("transfer"),
            &TMAddress::random(PREFIX),
        );

        let handler = super::Handler::new(
            ChainName::from_str("solana").unwrap(),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            EmptyResponseSolanaRpc,
            watch::channel(0).1,
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if it is not emitted from voting verifier
    #[tokio::test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            poll_started_event(participants(None), 100),
            &TMAddress::random(PREFIX),
        );

        let handler = super::Handler::new(
            ChainName::from_str("solana").unwrap(),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            EmptyResponseSolanaRpc,
            watch::channel(0).1,
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if worker is not a poll participant
    #[tokio::test]
    async fn verifier_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(None), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            ChainName::from_str("solana").unwrap(),
            TMAddress::random(PREFIX),
            voting_verifier,
            EmptyResponseSolanaRpc,
            watch::channel(0).1,
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    #[tokio::test]
    async fn should_vote_correctly() {
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            ChainName::from_str("solana").unwrap(),
            worker,
            voting_verifier,
            ValidResponseSolanaRpc,
            watch::channel(0).1,
        );

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn should_skip_expired_poll() {
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(Some(worker.clone())), expiration),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(
            ChainName::from_str("solana").unwrap(),
            worker,
            voting_verifier,
            ValidResponseSolanaRpc,
            rx,
        );

        // poll is not expired yet, should hit proxy
        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> VotingVerifierEvent {
        let signature_1 = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP";
        let event_idx_1 = 10_u32;
        let message_id_1 = format!("{signature_1}-{event_idx_1}");

        let signature_2 = "41SgBTfsWbkdixDdVNESM6YmDAzEcKEubGPkaXmtTVUd2EhMaqPEy3qh5ReTtTb4Le4F16SSBFjQCxkekamNrFNT";
        let event_idx_2 = 88_u32;
        let message_id_2 = format!("{signature_2}-{event_idx_2}");

        let source_gateway_address =
            Pubkey::from_str("4uX3jFnWLa4vBPyWJKd2XnUEX6JvP8q1BG7mTwQYhQeL").unwrap();

        VotingVerifierEvent::MessagesPollStarted {
            poll_id: "100".parse().unwrap(),
            source_chain: "solana".parse().unwrap(),
            source_gateway_address: source_gateway_address.to_string().parse().unwrap(),
            confirmation_height: 15,
            expires_at,
            participants: participants
                .into_iter()
                .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                .collect(),
            #[allow(deprecated)]
            messages: vec![
                TxEventConfirmation {
                    tx_id: signature_1.parse().unwrap(),
                    event_index: event_idx_1,
                    source_address: Pubkey::from_str(
                        "9Tp4XJZLQKdM82BHYfNAG6V3RWpLC7Y5mXo1UqKZFTJ3",
                    )
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                    message_id: message_id_1.parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: "0x3ad1f33ef5814e7adb43ed7fb39f9b45053ecab1"
                        .parse()
                        .unwrap(),
                    payload_hash: Hash::from_slice(&[1; 32]).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id: signature_2.parse().unwrap(),
                    event_index: event_idx_2,
                    source_address: Pubkey::from_str(
                        "H1QLZVpX7B4WMNY5UqKZG3RFTJ9M82BXoLQF26TJCY5N",
                    )
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                    message_id: message_id_2.parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: "0x3ad1f33ef5814e7adb43ed7fb39f9b45053ecab2"
                        .parse()
                        .unwrap(),
                    payload_hash: Hash::from_slice(&[2; 32]).to_fixed_bytes(),
                },
            ],
        }
    }

    fn participants(worker: Option<TMAddress>) -> Vec<TMAddress> {
        let mut participants = vec![
            AccountId::from_str("axelar1hg8mfs0pauxmxt5n76ndnlrye235zgz877l727")
                .unwrap()
                .into(),
            AccountId::from_str("axelar19neataahn59zsgex8479u9my28e0rae8c3hd6g")
                .unwrap()
                .into(),
            AccountId::from_str("axelar1fjh9eftylh82egzvcldmv5jyfuscvehqvxr8es")
                .unwrap()
                .into(),
            AccountId::from_str("axelar1s3gutkdnlr7gn9meanysm2muhz4g7w4x63ay0q")
                .unwrap()
                .into(),
            AccountId::from_str("axelar1k4mztxaugnqwf0hfp878785z887clvq2vkt7tq")
                .unwrap()
                .into(),
        ];

        if let Some(worker) = worker {
            participants.push(worker);
        }

        participants
    }
}
