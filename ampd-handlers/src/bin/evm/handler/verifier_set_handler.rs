use ampd::evm::json_rpc::EthereumClient;
use ampd::evm::verifier::verify_verifier_set;
use ampd::handlers::evm_verify_verifier_set::VerifierSetConfirmation;
use ampd::monitoring::metrics;
use ampd::types::EVMAddress;
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
#[try_from("wasm-verifier_set_poll_started")]
pub struct VerifierSetPollStarted {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: EVMAddress,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<AccountId>,
}

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    pub async fn handle_verifier_set<HC>(
        &self,
        event: VerifierSetPollStarted,
        client: &mut HC,
    ) -> crate::handler::Result<Vec<Any>>
    where
        HC: EventHandlerClient + Send + 'static,
    {
        let VerifierSetPollStarted {
            poll_id,
            source_chain,
            source_gateway_address,
            expires_at,
            confirmation_height,
            participants,
            verifier_set,
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

        let tx_hashes = [verifier_set.message_id.tx_hash.into()];

        let finalized_tx_receipts = self
            .finalized_tx_receipts(tx_hashes, confirmation_height)
            .await?;

        let poll_id_str = poll_id.to_string();
        let source_chain_str = source_chain.to_string();

        let vote = info_span!(
            "verify a new verifier set for an EVM chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            id = verifier_set.message_id.to_string()
        )
        .in_scope(|| {
            info!("ready to verify a new verifier set in poll");

            let vote = finalized_tx_receipts
                .get(&verifier_set.message_id.tx_hash.into())
                .map_or(Vote::NotFound, |tx_receipt| {
                    verify_verifier_set(&source_gateway_address, &tx_receipt, &verifier_set)
                });

            self.monitoring_client
                .metrics()
                .record_metric(metrics::Msg::VerificationVote {
                    vote_decision: vote.clone(),
                    chain_name: self.chain.clone(),
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
    use error_stack::Report;
    use ethers_core::types::{Block, H256, U64};
    use ethers_providers::ProviderError;
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use super::{Handler, VerifierSetPollStarted};

    const PREFIX: &str = "axelar";
    const ETHEREUM: &str = "ethereum";

    fn mock_handler_client(latest_block_height: u64) -> MockHandlerTaskClient {
        let mut client = MockHandlerTaskClient::new();
        client
            .expect_latest_block_height()
            .returning(move || Ok(latest_block_height));
        client
    }

    #[test]
    fn evm_verify_verifier_set_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: VerifierSetPollStarted = event.try_into().unwrap();

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

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
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
        let event: Event = into_structured_event(
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

        let metrics = receiver.recv().await.unwrap();

        assert_eq!(
            metrics,
            monitoring::metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: chain_name!(ETHEREUM),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_id = HexTxHashAndEventIndex::new(H256::repeat_byte(1), 100u64);
        PollStarted::VerifierSet {
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
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
        }
    }
}
