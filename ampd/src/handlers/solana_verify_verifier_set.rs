use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::{tx::Msg, Any};
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events_derive::try_from;
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use std::convert::TryInto;
use std::str::FromStr;
use tokio::sync::watch::Receiver;
use tracing::{error, info};

use axelar_wasm_std::voting::{PollId, Vote};
use router_api::ChainName;
use solana_client::nonblocking::rpc_client::RpcClient;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::solana::verifier_set_verifier::{parse_gateway_event, verify_verifier_set};
use crate::types::TMAddress;

use gmp_gateway::events::{ArchivedGatewayEvent, ArchivedRotateSignersEvent};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub tx_id: String,
    pub event_index: u32,
    pub verifier_set: VerifierSet,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-worker_set_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    _source_gateway_address: String,
    expires_at: u64,
    _confirmation_height: u64,
    participants: Vec<TMAddress>,
}

pub struct Handler {
    verifier: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: RpcClient,
    latest_block_height: Receiver<u64>,
}

impl Handler {
    pub fn new(
        verifier: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: RpcClient,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier,
            rpc_client,
            latest_block_height,
        }
    }

    fn vote_msg(&self, poll_id: PollId, votes: Vec<Vote>) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
                .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        let PollStartedEvent {
            contract_address,
            poll_id,
            expires_at,
            participants,
            verifier_set,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if self.voting_verifier != contract_address {
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

        let sol_tx_signature = match Signature::from_str(&verifier_set.tx_id) {
            Ok(sig) => sig,
            Err(err) => {
                error!(
                    poll_id = poll_id.to_string(),
                    err = err.to_string(),
                    "Cannot decode solana tx signature"
                );
                return Ok(vec![self
                    .vote_msg(poll_id, vec![Vote::FailedOnChain])
                    .into_any()
                    .expect("vote msg should serialize")]);
            }
        };

        let sol_tx = match self
            .rpc_client
            .get_transaction(&sol_tx_signature, UiTransactionEncoding::Json)
            .await
        {
            Ok(tx) => tx,
            Err(err) => match err.kind() {
                solana_client::client_error::ClientErrorKind::SerdeJson(err) => {
                    error!(
                        tx_signature = sol_tx_signature.to_string(),
                        err = err.to_string(),
                        poll_id = poll_id.to_string(),
                        "Could not find solana transaction."
                    );
                    return Ok(vec![self
                        .vote_msg(poll_id, vec![Vote::NotFound])
                        .into_any()
                        .expect("vote msg should serialize")]);
                }
                _ => {
                    error!(
                        tx_signature = sol_tx_signature.to_string(),
                        poll_id = poll_id.to_string(),
                        "RPC error while fetching transaction."
                    );
                    return Err(Error::TxReceipts)?;
                }
            },
        };

        let gw_event_container =
            parse_gateway_event(&sol_tx).map_err(|_| Error::DeserializeEvent)?;
        let gw_event = gw_event_container.parse();

        match gw_event {
            ArchivedGatewayEvent::SignersRotated(ArchivedRotateSignersEvent {
                new_signers_hash,
                ..
            }) => {
                let vote = verify_verifier_set(&verifier_set, new_signers_hash);
                Ok(vec![self
                    .vote_msg(poll_id, vec![vote])
                    .into_any()
                    .expect("vote msg should serialize")])
            }
            _ => {
                error!(
                    tx_signature = sol_tx_signature.to_string(),
                    poll_id = poll_id.to_string(),
                    "Error parsing gateway event."
                );
                return Ok(vec![self
                    .vote_msg(poll_id, vec![Vote::FailedOnChain])
                    .into_any()
                    .expect("vote msg should serialize")]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_wasm_std::nonempty;
    use multisig::{
        key::KeyType,
        test::common::{build_verifier_set, ecdsa_test_data},
    };
    use solana_client::rpc_request::RpcRequest;
    use tokio::sync::watch;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use crate::{
        handlers::tests::into_structured_event, solana::test_utils::rpc_client_with_recorder,
        PREFIX,
    };

    use tokio::test as async_test;

    use super::*;

    #[async_test]
    async fn must_abort_if_voting_verifier_is_same_as_contract_address() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        let handler = Handler::new(worker.clone(), voting_verifier.clone(), rpc_client, rx);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(2, Some(worker.clone())), expiration),
            &TMAddress::random(PREFIX),
        );

        let handler_result = handler.handle(&event).await.unwrap();

        assert!(handler_result.is_empty());
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
        );
    }

    #[async_test]
    async fn must_abort_chain_does_not_match() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        let handler = Handler::new(worker.clone(), voting_verifier.clone(), rpc_client, rx);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(2, Some(worker.clone())), expiration),
            &voting_verifier,
        );

        let handle_results = handler.handle(&event).await.unwrap();
        assert!(handle_results.is_empty());
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
        );
    }

    #[async_test]
    async fn must_abort_if_worker_is_not_participant() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        let handler = Handler::new(worker.clone(), voting_verifier.clone(), rpc_client, rx);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(2, None), expiration), // worker is not here.
            &voting_verifier,
        );

        let handle_results = handler.handle(&event).await.unwrap();
        assert!(handle_results.is_empty());
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
        );
    }

    #[async_test]
    async fn must_abort_on_expired_poll() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration);

        let handler = Handler::new(worker.clone(), voting_verifier.clone(), rpc_client, rx);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(2, Some(worker.clone())), expiration),
            &voting_verifier,
        );

        let handle_results = handler.handle(&event).await.unwrap();
        assert!(handle_results.is_empty());
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
        );
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let signature_1 = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP";
        let event_idx_1 = 10_u32;
        let message_id_1 = format!("{signature_1}-{event_idx_1}");

        #[allow(deprecated)]
        PollStarted::VerifierSet {
            verifier_set: VerifierSetConfirmation {
                tx_id: signature_1.parse().unwrap(),
                event_index: event_idx_1,
                message_id: message_id_1.parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "solana".parse().unwrap(),
                source_gateway_address: nonempty::String::from_str(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756a",
                )
                .unwrap(),
                confirmation_height: 1,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
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
