use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::Event;
use events_derive::try_from;
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::stacks::http_client::Client;
use crate::stacks::verifier::verify_verifier_set;
use crate::types::{Hash, TMAddress};

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub tx_id: Hash,
    pub event_index: u32,
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

pub struct Handler {
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    http_client: Client,
    latest_block_height: Receiver<u64>,
}

impl Handler {
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        http_client: Client,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            http_client,
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
impl EventHandler for Handler {
    type Err = Error;

    async fn handle(&self, event: &Event) -> error_stack::Result<Vec<Any>, Error> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_gateway_address,
            verifier_set,
            participants,
            expires_at,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![]);
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

        let transaction = self
            .http_client
            .get_valid_transaction(&verifier_set.tx_id)
            .await;

        let vote = info_span!(
            "verify a new verifier set for Stacks",
            poll_id = poll_id.to_string(),
            id = format!("{}_{}", verifier_set.tx_id, verifier_set.event_index)
        )
        .in_scope(|| {
            info!("ready to verify a new worker set in poll");

            let vote = transaction.map_or(Vote::NotFound, |transaction| {
                verify_verifier_set(&source_gateway_address, &transaction, verifier_set)
            });
            info!(
                vote = vote.as_value(),
                "ready to vote for a new worker set in poll"
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
    use std::collections::HashMap;
    use std::convert::TryInto;

    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use cosmwasm_std;
    use error_stack::Result;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{
        PollMetadata, PollStarted, TxEventConfirmation, VerifierSetConfirmation,
    };

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::into_structured_event;
    use crate::stacks::http_client::Client;
    use crate::types::{EVMAddress, Hash, TMAddress};
    use crate::PREFIX;

    #[test]
    fn should_deserialize_verifier_set_poll_started_event() {
        let event: Result<PollStartedEvent, events::Error> = into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into();

        assert!(event.is_ok());

        let event = event.unwrap();

        assert!(event.poll_id == 100u64.into());
        assert!(
            event.source_gateway_address
                == "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway"
        );

        let verifier_set = event.verifier_set;

        assert!(
            verifier_set.tx_id
                == "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
                    .parse()
                    .unwrap()
        );
        assert!(verifier_set.event_index == 1u32);
        assert!(verifier_set.verifier_set.signers.len() == 3);
        assert_eq!(verifier_set.verifier_set.threshold, Uint128::from(2u128));

        let mut signers = verifier_set.verifier_set.signers.values();
        let signer1 = signers.next().unwrap();
        let signer2 = signers.next().unwrap();

        assert_eq!(signer1.pub_key.as_ref(), HexBinary::from_hex(
            "45e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f",
        )
            .unwrap().as_ref());
        assert_eq!(signer1.weight, Uint128::from(1u128));

        assert_eq!(signer2.pub_key.as_ref(), HexBinary::from_hex(
            "dd9822c7fa239dda9913ebee813ecbe69e35d88ff651548d5cc42c033a8a667b",
        )
            .unwrap().as_ref());
        assert_eq!(signer2.weight, Uint128::from(1u128));
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "multiversx".parse().unwrap(),
                source_gateway_address: "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway"
                    .parse()
                    .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            verifier_set: VerifierSetConfirmation {
                tx_id: "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
                    .parse()
                    .unwrap(),
                event_index: 1,
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
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
