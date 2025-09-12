use std::collections::{HashMap, HashSet};
use std::str::FromStr as _;

use async_trait::async_trait;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, Event};
use futures::stream::{self, StreamExt};
use router_api::ChainName;
use serde::{Deserialize, Serialize};
use snarkvm::prelude::{Address, Network, ProgramID};
use tokio::sync::watch::Receiver;
use tracing::{debug, info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::aleo::http_client::ClientTrait as AleoClientTrait;
use crate::aleo::{CallContractReceipt, Receipt, ReceiptBuilder};
use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::types::{Hash, TMAddress};

#[derive(Deserialize, Serialize, Debug)]
#[serde(bound = "Address<N>: Serialize + for<'a> Deserialize<'a>")]
pub struct Message<N>
where
    N: Network,
{
    pub tx_id: N::TransitionID,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: Address<N>,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[serde(bound = "Vec<Message<N>>: for<'a> Deserialize<'a>")]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent<N>
where
    N: Network,
{
    poll_id: PollId,
    source_chain: ChainName,
    expires_at: u64,
    participants: Vec<TMAddress>,
    messages: Vec<Message<N>>,
}

#[derive(Clone)]
pub struct Handler<N: Network, C: AleoClientTrait<N>> {
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    http_client: C,
    latest_block_height: Receiver<u64>,
    chain: ChainName,
    gateway_contract: ProgramID<N>,
}

impl<N, C> Handler<N, C>
where
    N: Network,
    C: AleoClientTrait<N> + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        chain: ChainName,
        aleo_client: C,
        latest_block_height: Receiver<u64>,
        gateway_contract: &str,
    ) -> Result<Self, crate::aleo::error::Error> {
        Ok(Self {
            verifier,
            voting_verifier_contract,
            http_client: aleo_client,
            latest_block_height,
            chain,
            gateway_contract: ProgramID::from_str(gateway_contract)?,
        })
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
}

async fn fetch_transition_receipt<N, C>(
    http_client: &C,
    program: &ProgramID<N>,
    id: N::TransitionID,
) -> Result<(N::TransitionID, Receipt<N, CallContractReceipt<N>>), Error>
where
    N: Network,
    C: AleoClientTrait<N> + Send + Sync + 'static,
{
    let receipt = async {
        ReceiptBuilder::new(http_client, program)?
            .get_transaction_id(&id)
            .await?
            .get_transaction()
            .await?
            .get_transition()?
            .check_call_contract()
    }
    .await;

    let res = match receipt {
        Ok(receipt) => (id, receipt),
        Err(e) => (id, Receipt::NotFound(id, e)),
    };

    Ok(res)
}

#[async_trait]
impl<N, C> EventHandler for Handler<N, C>
where
    N: Network,
    C: AleoClientTrait<N> + Send + Sync + 'static,
{
    type Err = Error;

    #[tracing::instrument(skip(self, event))]
    async fn handle(&self, event: &Event) -> error_stack::Result<Vec<Any>, Self::Err> {
        debug!("event: {event:?}");
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            expires_at,
            participants,
            messages,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
        };

        if self.chain != source_chain {
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        if *self.latest_block_height.borrow() >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        // Transition IDs on Aleo chain
        let transitions: HashSet<N::TransitionID> =
            messages.iter().map(|m: &Message<N>| m.tx_id).collect();

        let transition_receipts: HashMap<_, _> = stream::iter(transitions)
            .map(|id| async move {
                match fetch_transition_receipt(&self.http_client, &self.gateway_contract, id).await
                {
                    Ok((transition, receipt)) => Some((transition, receipt)),
                    Err(_) => None,
                }
            })
            .buffer_unordered(10)
            .filter_map(|item| async { item })
            .collect()
            .await;

        let poll_id_str: String = poll_id.into();
        let source_chain_str: String = source_chain.into();
        let votes = info_span!(
            "verify messages from an Aleo chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            message_ids = messages
                .iter()
                .map(|msg: &Message<N>| msg.tx_id.to_string())
                .collect::<Vec<String>>()
                .as_value(),
        )
        .in_scope(|| {
            info!("ready to verify messages in poll");

            let votes: Vec<_> = messages
                .iter()
                .map(|msg| {
                    transition_receipts
                        .get(&msg.tx_id)
                        .map_or(Vote::NotFound, |tx_receipt| {
                            crate::aleo::verifier::verify_message::<N>(tx_receipt, msg)
                        })
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
    use std::str::FromStr;

    use cosmrs::AccountId;

    use super::*;
    use crate::types::TMAddress;

    type CurrentNetwork = snarkvm::prelude::TestnetV0;

    use cosmrs::proto::cosmwasm::wasm::v1::MsgExecuteContract;
    use prost::Message as _;

    fn poll_started_event() -> Event {
        let expires_at: u64 = 10;
        let participants: Vec<TMAddress> = vec![AccountId::from_str(
            "axelar1a9d3a3hcykzfa8rn3y7d47ns55x3wdlykchydd8x3f95dtz9qh0q3vnrg0",
        )
        .unwrap()
        .into()];
        let messages: Vec<Message<CurrentNetwork>> = vec![Message {
            tx_id: <CurrentNetwork as snarkvm::prelude::Network>::TransitionID::from_str(
                "au130u5y9kvf7rf6663tlamkaq9549gzddkkf7cd2997aaedglxdcqsl6pxl4",
            )
            .unwrap(),
            destination_address: "helloworld.aleo".to_string(),
            destination_chain: ChainName::from_str("aleo-2").unwrap(),
            source_address: Address::<CurrentNetwork>::from_str(
                "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t",
            )
            .unwrap(),
            payload_hash: Hash::from_str(
                "54052273bc5d7afe1080d5760588cbe0b9889cb43804d68697f4b698bf116e8e",
            )
            .unwrap(),
        }];

        let v: Vec<(String, serde_json::Value)> = vec![
            (
                "poll_id".to_string(),
                serde_json::to_value(PollId::from(100)).unwrap(),
            ),
            (
                "_contract_address".to_string(),
                serde_json::to_value(
                    "axelar1a9d3a3hcykzfa8rn3y7d47ns55x3wdlykchydd8x3f95dtz9qh0q3vnrg0",
                )
                .unwrap(),
            ),
            (
                "source_chain".to_string(),
                serde_json::to_value("aleo-2").unwrap(),
            ),
            (
                "source_gateway_address".to_string(),
                serde_json::to_value("gateway_frontend.aleo").unwrap(),
            ),
            (
                "expires_at".to_string(),
                serde_json::to_value(expires_at).unwrap(),
            ),
            (
                "participants".to_string(),
                serde_json::to_value(participants).unwrap(),
            ),
            (
                "messages".to_string(),
                serde_json::to_value(messages).unwrap(),
            ),
        ];

        let json_map: serde_json::Map<String, serde_json::Value> = v.into_iter().collect();

        Event::Abci {
            event_type: "wasm-messages_poll_started".to_string(),
            attributes: json_map,
        }
    }

    #[tokio::test]
    async fn aleo_verify_msg() {
        let transaction_id = "at188kfg7uxqc0rpzlq66y7mp293a5vauqr5jdlg3a7v9tk9wpsavgqe7ww5l";
        let mock_client = crate::aleo::http_client::tests::mock_client(
            transaction_id,
            include_str!(
                "../tests/at188kfg7uxqc0rpzlq66y7mp293a5vauqr5jdlg3a7v9tk9wpsavgqe7ww5l.json"
            ),
        );
        let event = poll_started_event();

        let handler = Handler::<CurrentNetwork, _>::new(
            TMAddress::from(
                AccountId::from_str(
                    "axelar1a9d3a3hcykzfa8rn3y7d47ns55x3wdlykchydd8x3f95dtz9qh0q3vnrg0",
                )
                .unwrap(),
            ),
            TMAddress::from(
                AccountId::from_str(
                    "axelar1a9d3a3hcykzfa8rn3y7d47ns55x3wdlykchydd8x3f95dtz9qh0q3vnrg0",
                )
                .unwrap(),
            ),
            ChainName::from_str("aleo-2").unwrap(),
            mock_client,
            tokio::sync::watch::channel(0).1,
            "gateway_frontend.aleo",
        )
        .unwrap();

        let res = handler.handle(&event).await.unwrap();
        let res: Vec<MsgExecuteContract> = res
            .iter()
            .map(|msg| MsgExecuteContract::decode(msg.value.as_slice()).unwrap())
            .collect();

        println!("res: {:?}", res);

        for r in res {
            let decode: ExecuteMsg = serde_json::from_slice(&r.msg).unwrap();
            match decode {
                ExecuteMsg::Vote { poll_id, votes } => {
                    assert_eq!(poll_id, PollId::from(100));
                    assert_eq!(votes.len(), 1);
                    assert!(matches!(votes[0], Vote::SucceededOnChain));
                }
                _ => panic!("Unexpected message type: {:?}", decode),
            }
        }
    }
}
