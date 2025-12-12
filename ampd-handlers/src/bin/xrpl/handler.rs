use std::collections::{HashMap, HashSet};

use ampd::monitoring;
use ampd::xrpl::json_rpc::XRPLClient;
use ampd::xrpl::verifier::verify_message;
use ampd_handlers::voting::{self, Error, PollEventData as _, VotingHandler};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::nonempty;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::{AccountId, Any};
use events::{try_from, AbciEventTypeFilter, EventType};
use futures::future::join_all;
use serde::Deserialize;
use typed_builder::TypedBuilder;
use xrpl_http_client::Transaction;
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::{xrpl_account_id_string, XRPLAccountId};

pub type Result<T> = error_stack::Result<T, Error>;

// Message poll event struct
#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-messages_poll_started")]
pub struct MessagesPollStarted {
    poll_id: PollId,
    source_chain: ChainName,
    #[serde(with = "xrpl_account_id_string")]
    source_gateway_address: XRPLAccountId,
    expires_at: u64,
    messages: Vec<XRPLMessage>,
    confirmation_height: u64,
    participants: Vec<AccountId>,
}

#[derive(Clone, Debug)]
pub struct PollEventData {
    message: XRPLMessage,
    message_id: nonempty::String,
}

impl PollEventData {
    pub fn new(message: XRPLMessage) -> Self {
        let message_id = message.tx_id().tx_hash_as_hex();
        Self {
            message,
            message_id,
        }
    }
}
impl voting::PollEventData for PollEventData {
    type Digest = HexTxHash;
    type MessageId = nonempty::String;
    type ChainAddress = XRPLAccountId;
    type Receipt = Transaction;

    fn tx_hash(&self) -> Self::Digest {
        self.message.tx_id()
    }

    fn message_id(&self) -> &Self::MessageId {
        &self.message_id
    }

    fn verify(
        &self,
        source_gateway_address: &Self::ChainAddress,
        tx_receipt: &Self::Receipt,
    ) -> Vote {
        verify_message(source_gateway_address, tx_receipt, &self.message)
    }
}

impl From<MessagesPollStarted> for voting::PollStartedEvent<PollEventData, XRPLAccountId> {
    fn from(event: MessagesPollStarted) -> Self {
        voting::PollStartedEvent {
            poll_data: event.messages.into_iter().map(PollEventData::new).collect(),
            poll_id: event.poll_id,
            source_chain: event.source_chain,
            source_gateway_address: event.source_gateway_address,
            expires_at: event.expires_at,
            confirmation_height: event.confirmation_height,
            participants: event.participants,
        }
    }
}

#[derive(Debug, TypedBuilder)]
pub struct Handler<C>
where
    C: XRPLClient,
{
    pub verifier: AccountId,
    pub voting_verifier_contract: AccountId,
    pub chain: ChainName,
    pub rpc_client: C,
    pub monitoring_client: monitoring::Client,
}

#[async_trait]
impl<C> VotingHandler for Handler<C>
where
    C: XRPLClient + Send + Sync,
{
    type Digest = HexTxHash;
    type Receipt = Transaction;
    type ChainAddress = XRPLAccountId;
    type EventData = PollEventData;

    fn chain(&self) -> &ChainName {
        &self.chain
    }

    fn verifier(&self) -> &AccountId {
        &self.verifier
    }

    fn voting_verifier_contract(&self) -> &AccountId {
        &self.voting_verifier_contract
    }

    fn monitoring_client(&self) -> &monitoring::Client {
        &self.monitoring_client
    }

    async fn finalized_txs(
        &self,
        poll_data: &[Self::EventData],
        _confirmation_height: Option<u64>,
    ) -> Result<HashMap<Self::Digest, Self::Receipt>> {
        let tx_ids: HashSet<_> = poll_data.iter().map(|data| data.tx_hash()).collect();

        let txs = join_all(tx_ids.into_iter().map(|tx_id| async move {
            let result = self.rpc_client.tx(tx_id.tx_hash).await;
            (tx_id, result)
        }))
        .await
        .into_iter()
        .filter_map(|(hex_tx_hash, result)| {
            let tx_res = result.ok().flatten()?;
            let tx = tx_res.tx;
            let tx_common = tx.common();

            if tx_common.validated != Some(true) {
                return None;
            }

            Some((hex_tx_hash, tx))
        })
        .collect();

        Ok(txs)
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: XRPLClient + Send + Sync,
{
    type Err = Error;
    type Event = MessagesPollStarted;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        event: MessagesPollStarted,
        client: &mut HC,
    ) -> Result<Vec<Any>> {
        VotingHandler::handle(self, event.into(), client).await
    }

    fn subscription_params(&self) -> SubscriptionParams {
        let attributes = HashMap::from([(
            "source_chain".to_string(),
            serde_json::Value::String(self.chain.to_string()),
        )]);

        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: MessagesPollStarted::event_type(),
                contract: self.voting_verifier_contract.clone(),
                attributes,
            }],
            false,
        )
    }
}
