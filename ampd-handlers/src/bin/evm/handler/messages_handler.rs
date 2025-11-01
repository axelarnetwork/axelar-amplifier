use std::collections::HashSet;

use ampd::evm::json_rpc::EthereumClient;
use ampd::evm::verifier::verify_message;
use ampd::handlers::evm_verify_msg::Message;
use ampd::monitoring::metrics;
use ampd::types::{EVMAddress, Hash};
use ampd_sdk::grpc::client::EventHandlerClient;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use events::try_from;
use serde::Deserialize;
use tracing::{info, info_span};
use valuable::Valuable;

use crate::handler::Handler;

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-messages_poll_started")]
pub struct MessagesPollStarted {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: EVMAddress,
    confirmation_height: u64,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<AccountId>,
}

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    pub async fn handle_messages<HC>(
        &self,
        event: MessagesPollStarted,
        client: &mut HC,
    ) -> crate::handler::Result<Vec<Any>>
    where
        HC: EventHandlerClient + Send + 'static,
    {
        let MessagesPollStarted {
            poll_id,
            source_chain,
            source_gateway_address,
            messages,
            expires_at,
            confirmation_height,
            participants,
        } = event;

        if self
            .should_skip_handling(
                client,
                source_chain.clone(),
                participants,
                expires_at,
                poll_id,
            )
            .await?
        {
            return Ok(vec![]);
        }

        let tx_hashes: HashSet<Hash> = messages
            .iter()
            .map(|msg| msg.message_id.tx_hash.into())
            .collect();

        let finalized_tx_receipts = self
            .finalized_tx_receipts(tx_hashes, confirmation_height)
            .await?;

        let poll_id_str: String = poll_id.to_string();
        let source_chain_str: String = source_chain.to_string();

        let votes = info_span!(
            "verify messages from an EVM chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
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
                        .get(&msg.message_id.tx_hash.into())
                        .map_or(Vote::NotFound, |tx_receipt| {
                            verify_message(&source_gateway_address, tx_receipt, msg)
                        })
                })
                .inspect(|vote| {
                    self.monitoring_client.metrics().record_metric(
                        metrics::Msg::VerificationVote {
                            vote_decision: vote.clone(),
                            chain_name: self.chain.clone(),
                        },
                    );
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
mod tests {
    use std::convert::TryInto;

    use ampd::evm::finalizer::Finalization;
    use ampd::evm::json_rpc::MockEthereumClient;
    use ampd::handlers::test_utils::{into_structured_event, participants};
    use ampd::monitoring;
    use ampd::types::{Hash, TMAddress};
    use ampd_sdk::event::event_handler::EventHandler;
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::chain_name;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use error_stack::{Report, Result};
    use ethers_core::types::{Block, H160, H256, U64};
    use ethers_providers::ProviderError;
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::{Handler, MessagesPollStarted};

    const PREFIX: &str = "axelar";
    const ETHEREUM: &str = "ethereum";

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_ids = [
            HexTxHashAndEventIndex::new(H256::repeat_byte(1), 0u64),
            HexTxHashAndEventIndex::new(H256::repeat_byte(2), 1u64),
            HexTxHashAndEventIndex::new(H256::repeat_byte(3), 10u64),
        ];
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!(ETHEREUM),
                source_gateway_address: "0x4f4495243837681061c4743b74eedf548d5686a5"
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
            messages: vec![
                TxEventConfirmation {
                    message_id: msg_ids[0].to_string().parse().unwrap(),
                    source_address: format!("0x{:x}", H160::repeat_byte(1)).parse().unwrap(),
                    destination_chain: chain_name!(ETHEREUM),
                    destination_address: format!("0x{:x}", H160::repeat_byte(2)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(4).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    message_id: msg_ids[1].to_string().parse().unwrap(),
                    source_address: format!("0x{:x}", H160::repeat_byte(3)).parse().unwrap(),
                    destination_chain: chain_name!(ETHEREUM),
                    destination_address: format!("0x{:x}", H160::repeat_byte(4)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(5).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    message_id: msg_ids[2].to_string().parse().unwrap(),
                    source_address: format!("0x{:x}", H160::repeat_byte(5)).parse().unwrap(),
                    destination_chain: chain_name!(ETHEREUM),
                    destination_address: format!("0x{:x}", H160::repeat_byte(6)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(6).to_fixed_bytes(),
                },
            ],
        }
    }

    fn mock_handler_client(latest_block_height: u64) -> MockHandlerTaskClient {
        let mut client = MockHandlerTaskClient::new();
        client
            .expect_latest_block_height()
            .returning(move || Ok(latest_block_height));
        client
    }

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
        let event: Result<MessagesPollStarted, events::Error> = (&event).try_into();

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

        let event: Result<MessagesPollStarted, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn evm_verify_msg_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: MessagesPollStarted = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut rpc_client = MockEthereumClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client.expect_finalized_block().returning(|| {
            Err(Report::from(ProviderError::CustomError(
                "failed to get finalized block".to_string(),
            )))
        });

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier_contract,
        );

        let (monitoring_client, _) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier_contract.into())
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        // poll is not expired yet, should hit rpc error
        assert!(handler
            .handle(event.clone().try_into().unwrap(), &mut client)
            .await
            .is_err());

        let mut client = mock_handler_client(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(
            handler
                .handle(event.try_into().unwrap(), &mut client)
                .await
                .unwrap(),
            vec![]
        );
    }

    #[async_test]
    async fn should_record_verification_vote_metric() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        rpc_client
            .expect_transaction_receipt()
            .returning(|_| Ok(None));

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier_contract,
        );
        let (monitoring_client, mut receiver) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier_contract.into())
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(0);

        assert!(handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .is_ok());

        for _ in 0..3 {
            let metrics = receiver.recv().await.unwrap();

            assert_eq!(
                metrics,
                monitoring::metrics::Msg::VerificationVote {
                    vote_decision: Vote::NotFound,
                    chain_name: chain_name!(ETHEREUM),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }
}
