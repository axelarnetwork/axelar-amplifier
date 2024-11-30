use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::{Base58SolanaTxSignatureAndEventIndex, HexTxHashAndEventIndex};
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events_derive::try_from;
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;
use serde::Deserialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiTransactionStatusMeta;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::solana::verifier_set_verifier::verify_verifier_set;
use crate::solana::SolanaRpcClientProxy;
use crate::types::TMAddress;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub message_id: Base58SolanaTxSignatureAndEventIndex,
    pub verifier_set: VerifierSet,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    #[serde(deserialize_with = "crate::solana::deserialize_pubkey")]
    source_gateway_address: Pubkey,
    expires_at: u64,
    participants: Vec<TMAddress>,
}

pub struct Handler<C: SolanaRpcClientProxy> {
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    solana_gateway_domain_separator: [u8; 32],
    latest_block_height: Receiver<u64>,
}

impl<C: SolanaRpcClientProxy> Handler<C> {
    pub async fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        let domain_separator = rpc_client
            .get_domain_separator()
            .await
            .expect("cannot start handler without fetching domain separator for Solana");

        Self {
            verifier,
            solana_gateway_domain_separator: domain_separator,
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

    async fn fetch_message(
        &self,
        msg: &VerifierSetConfirmation,
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

        let tx_receipt = self.fetch_message(&verifier_set).await;
        let vote = info_span!(
            "verify a new verifier set for Solana",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            id = verifier_set.message_id.to_string()
        )
        .in_scope(|| {
            info!("ready to verify a new verifier set in poll");

            let vote = tx_receipt.map_or(Vote::NotFound, |(_, tx_receipt)| {
                verify_verifier_set(
                    &source_gateway_address,
                    &tx_receipt,
                    &verifier_set,
                    &self.solana_gateway_domain_separator,
                )
            });
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
    use std::str::FromStr;

    // use axelar_wasm_std::nonempty;
    // use multisig::{
    //     key::KeyType,
    //     test::common::{build_verifier_set, ecdsa_test_data},
    // };
    // use solana_client::rpc_request::RpcRequest;
    // use tokio::sync::watch;
    // use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    // use crate::{
    //     handlers::tests::into_structured_event, solana::test_utils::rpc_client_with_recorder,
    //     PREFIX,
    // };

    // use tokio::test as async_test;

    // use super::*;

    // #[async_test]
    // async fn must_abort_if_voting_verifier_is_same_as_contract_address() {
    //     let worker = TMAddress::random(PREFIX);
    //     let voting_verifier = TMAddress::random(PREFIX);

    //     let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

    //     let expiration = 100u64;
    //     let (_, rx) = watch::channel(expiration - 1);

    //     let handler = Handler::new(worker.clone(), voting_verifier.clone(), rpc_client, rx);

    //     let event = into_structured_event(
    //         verifier_set_poll_started_event(participants(2, Some(worker.clone())), expiration),
    //         &TMAddress::random(PREFIX),
    //     );

    //     let handler_result = handler.handle(&event).await.unwrap();

    //     assert!(handler_result.is_empty());
    //     assert_eq!(
    //         None,
    //         rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
    //     );
    //     assert_eq!(
    //         None,
    //         rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
    //     );
    // }

    // #[async_test]
    // async fn must_abort_chain_does_not_match() {
    //     let worker = TMAddress::random(PREFIX);
    //     let voting_verifier = TMAddress::random(PREFIX);

    //     let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

    //     let expiration = 100u64;
    //     let (_, rx) = watch::channel(expiration - 1);

    //     let handler = Handler::new(worker.clone(), voting_verifier.clone(), rpc_client, rx);

    //     let event = into_structured_event(
    //         verifier_set_poll_started_event(participants(2, Some(worker.clone())), expiration),
    //         &voting_verifier,
    //     );

    //     let handle_results = handler.handle(&event).await.unwrap();
    //     assert!(handle_results.is_empty());
    //     assert_eq!(
    //         None,
    //         rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
    //     );
    //     assert_eq!(
    //         None,
    //         rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
    //     );
    // }

    // #[async_test]
    // async fn must_abort_if_worker_is_not_participant() {
    //     let worker = TMAddress::random(PREFIX);
    //     let voting_verifier = TMAddress::random(PREFIX);

    //     let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

    //     let expiration = 100u64;
    //     let (_, rx) = watch::channel(expiration - 1);

    //     let handler = Handler::new(worker.clone(), voting_verifier.clone(), rpc_client, rx);

    //     let event = into_structured_event(
    //         verifier_set_poll_started_event(participants(2, None), expiration), // worker is not here.
    //         &voting_verifier,
    //     );

    //     let handle_results = handler.handle(&event).await.unwrap();
    //     assert!(handle_results.is_empty());
    //     assert_eq!(
    //         None,
    //         rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
    //     );
    //     assert_eq!(
    //         None,
    //         rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
    //     );
    // }

    // #[async_test]
    // async fn must_abort_on_expired_poll() {
    //     let worker = TMAddress::random(PREFIX);
    //     let voting_verifier = TMAddress::random(PREFIX);

    //     let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

    //     let expiration = 100u64;
    //     let (_, rx) = watch::channel(expiration);

    //     let handler = Handler::new(worker.clone(), voting_verifier.clone(), rpc_client, rx);

    //     let event = into_structured_event(
    //         verifier_set_poll_started_event(participants(2, Some(worker.clone())), expiration),
    //         &voting_verifier,
    //     );

    //     let handle_results = handler.handle(&event).await.unwrap();
    //     assert!(handle_results.is_empty());
    //     assert_eq!(
    //         None,
    //         rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
    //     );
    //     assert_eq!(
    //         None,
    //         rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
    //     );
    // }

    // fn verifier_set_poll_started_event(
    //     participants: Vec<TMAddress>,
    //     expires_at: u64,
    // ) -> PollStarted {
    //     let signature_1 = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP";
    //     let event_idx_1 = 10_u32;
    //     let message_id_1 = format!("{signature_1}-{event_idx_1}");

    //     #[allow(deprecated)]
    //     PollStarted::VerifierSet {
    //         verifier_set: VerifierSetConfirmation {
    //             tx_id: signature_1.parse().unwrap(),
    //             event_index: event_idx_1,
    //             message_id: message_id_1.parse().unwrap(),
    //             verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
    //         },
    //         metadata: PollMetadata {
    //             poll_id: "100".parse().unwrap(),
    //             source_chain: "solana".parse().unwrap(),
    //             source_gateway_address: nonempty::String::from_str(
    //                 "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756a",
    //             )
    //             .unwrap(),
    //             confirmation_height: 1,
    //             expires_at,
    //             participants: participants
    //                 .into_iter()
    //                 .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
    //                 .collect(),
    //         },
    //     }
    // }

    // fn participants(n: u8, worker: Option<TMAddress>) -> Vec<TMAddress> {
    //     (0..n)
    //         .map(|_| TMAddress::random(PREFIX))
    //         .chain(worker)
    //         .collect()
    // }
}
