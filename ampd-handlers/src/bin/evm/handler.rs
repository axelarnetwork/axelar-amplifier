use std::collections::{HashMap, HashSet};

use ampd::evm::finalizer::{self, Finalization};
use ampd::evm::json_rpc::EthereumClient;
use ampd::types::{EVMAddress, Hash};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};

use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::{AccountId, Any};
use error_stack::ResultExt;
use ethers_core::types::{TransactionReceipt, U64};
use events::{try_from, AbciEventTypeFilter};
use futures::future::join_all;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use typed_builder::TypedBuilder;
use voting_verifier::msg::ExecuteMsg;

use crate::Error;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub message_id: HexTxHashAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: EVMAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
pub struct PollStartedEvent {
    #[serde(rename(deserialize = "_contract_address"))]
    contract_address: AccountId,
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: EVMAddress,
    confirmation_height: u64,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<AccountId>,
}

#[derive(Debug, TypedBuilder)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    verifier: AccountId,
    voting_verifier_contract: AccountId,
    chain: ChainName,
    finalizer_type: Finalization,
    rpc_client: C,
}

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    async fn finalized_tx_receipts<T>(
        &self,
        tx_hashes: T,
        confirmation_height: u64,
    ) -> Result<HashMap<Hash, TransactionReceipt>>
    where
        T: IntoIterator<Item = Hash>,
    {
        let latest_finalized_block_height =
            finalizer::pick(&self.finalizer_type, &self.rpc_client, confirmation_height)
                .latest_finalized_block_height()
                .await
                .change_context(Error::Finalizer)?;

        Ok(join_all(
            tx_hashes
                .into_iter()
                .map(|tx_hash| self.rpc_client.transaction_receipt(tx_hash)),
        )
        .await
        .into_iter()
        .filter_map(std::result::Result::unwrap_or_default)
        .filter_map(|tx_receipt| {
            if tx_receipt
                .block_number
                .unwrap_or(U64::MAX)
                .le(&latest_finalized_block_height)
            {
                Some((tx_receipt.transaction_hash, tx_receipt))
            } else {
                None
            }
        })
        .collect())
    }

    fn vote_msg(&self, poll_id: PollId, votes: Vec<Vote>) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.clone(),
            contract: self.voting_verifier_contract.clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
                .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    type Err = Error;
    type Event = PollStartedEvent;

    async fn handle(
        &self,
        event: &PollStartedEvent,
        _token: CancellationToken,
    ) -> Result<Vec<Any>> {
        let PollStartedEvent {
            contract_address,
            poll_id,
            source_chain,
            source_gateway_address,
            messages,
            expires_at,
            confirmation_height,
            participants,
        } = event;

        if contract_address != &self.voting_verifier_contract {
            return Ok(vec![]);
        }

        if source_chain != &self.chain {
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        // TODO: skip expired poll

        let tx_hashes: HashSet<Hash> = messages
            .iter()
            .map(|msg| msg.message_id.tx_hash.into())
            .collect();

        Ok(vec![])
    }

    fn subscription_params(&self) -> SubscriptionParams {
        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: "wasm-messages_poll_started".to_string(),
            }], // TODO: Add verifier set poll started event filter?
            false,
        )
    }
}
