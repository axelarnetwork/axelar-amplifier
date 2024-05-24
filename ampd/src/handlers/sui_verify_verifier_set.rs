use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::{tx::Msg, Any};
use cosmwasm_std::HexBinary;
use cosmwasm_std::Uint128;
use error_stack::ResultExt;
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;
use sui_types::base_types::{SuiAddress, TransactionDigest};
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;

use axelar_wasm_std::msg_id::base_58_event_index::Base58TxDigestAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::sui::json_rpc::SuiClient;
use crate::sui::verifier::verify_worker_set;
use crate::types::TMAddress;

#[derive(Deserialize, Debug)]
pub struct Operators {
    pub weights_by_addresses: Vec<(HexBinary, Uint128)>,
    pub threshold: Uint128,
}

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub tx_id: TransactionDigest,
    pub event_index: u32,
    pub verifier_set: VerifierSet,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_gateway_address: SuiAddress,
    verifier_set: VerifierSetConfirmation,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler<C>
where
    C: SuiClient + Send + Sync,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C> Handler<C>
where
    C: SuiClient + Send + Sync,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            rpc_client,
            latest_block_height,
        }
    }

    fn vote_msg(&self, poll_id: PollId, vote: Vote) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.worker.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
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
    C: SuiClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> error_stack::Result<Vec<Any>, Error> {
        if !event.is_from_contract(self.voting_verifier.as_ref()) {
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

        if !participants.contains(&self.worker) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let transaction_block = self
            .rpc_client
            .finalized_transaction_block(verifier_set.tx_id)
            .await
            .change_context(Error::TxReceipts)?;

        let vote = info_span!(
            "verify a new worker set for Sui",
            poll_id = poll_id.to_string(),
            id = Base58TxDigestAndEventIndex::new(verifier_set.tx_id, verifier_set.event_index)
                .to_string()
        )
        .in_scope(|| {
            let vote = transaction_block.map_or(Vote::NotFound, |tx_receipt| {
                verify_worker_set(&source_gateway_address, &tx_receipt, &verifier_set)
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
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use error_stack::{Report, Result};
    use ethers::providers::ProviderError;
    use multisig::key::PublicKey;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use sui_types::base_types::{SuiAddress, TransactionDigest};
    use tokio::sync::watch;
    use tokio::test as async_test;

    use axelar_wasm_std::operators::Operators;
    use events::Event;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use crate::event_processor::EventHandler;
    use crate::handlers::sui_verify_verifier_set;
    use crate::sui::json_rpc::MockSuiClient;
    use crate::PREFIX;
    use crate::{handlers::tests::get_event, types::TMAddress};

    use super::PollStartedEvent;

    #[test]
    fn should_deserialize_worker_set_poll_started_event() {
        let participants = (0..5).map(|_| TMAddress::random(PREFIX)).collect();

        let event: Result<PollStartedEvent, events::Error> = get_event(
            worker_set_poll_started_event(participants, 100),
            &TMAddress::random(PREFIX),
        )
        .try_into();

        assert!(event.is_ok());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut rpc_client = MockSuiClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client
            .expect_finalized_transaction_block()
            .returning(|_| {
                Err(Report::from(ProviderError::CustomError(
                    "failed to get finalized transaction blocks".to_string(),
                )))
            });

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = get_event(
            worker_set_poll_started_event(vec![worker.clone()].into_iter().collect(), expiration),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler =
            sui_verify_verifier_set::Handler::new(worker, voting_verifier, rpc_client, rx);

        // poll is not expired yet, should hit rpc error
        assert!(handler.handle(&event).await.is_err());

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    pub fn new_verifier_set() -> VerifierSet {
        let signers = vec![
            Signer {
                address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
                    )
                    .unwrap(),
                ),
            },
            Signer {
                address: Addr::unchecked("axelarvaloper1ff675m593vve8yh82lzhdnqfpu7m23cxstr6h4"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "03c6ddb0fcee7b528da1ef3c9eed8d51eeacd7cc28a8baa25c33037c5562faa6e4",
                    )
                    .unwrap(),
                ),
            },
            Signer {
                address: Addr::unchecked("axelarvaloper12cwre2gdhyytc3p97z9autzg27hmu4gfzz4rxc"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "0274b5d2a4c55d7edbbf9cc210c4d25adbb6194d6b444816235c82984bee518255",
                    )
                    .unwrap(),
                ),
            },
            Signer {
                address: Addr::unchecked("axelarvaloper1vs9rdplntrf7ceqdkznjmanrr59qcpjq6le0yw"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "02a670f57de55b8b39b4cb051e178ca8fb3fe3a78cdde7f8238baf5e6ce1893185",
                    )
                    .unwrap(),
                ),
            },
            Signer {
                address: Addr::unchecked("axelarvaloper1hz0slkejw96dukw87fztjkvwjdpcu20jewg6mw"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "028584592624e742ba154c02df4c0b06e4e8a957ba081083ea9fe5309492aa6c7b",
                    )
                    .unwrap(),
                ),
            },
        ];

        let mut btree_signers = BTreeMap::new();
        for signer in signers {
            btree_signers.insert(signer.address.clone().to_string(), signer);
        }

        VerifierSet {
            signers: btree_signers,
            threshold: Uint128::from(30u128),
            created_at: 1,
        }
    }

    fn worker_set_poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "sui".parse().unwrap(),
                source_gateway_address: SuiAddress::random_for_testing_only()
                    .to_string()
                    .parse()
                    .unwrap(),
                confirmation_height: 1,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            verifier_set: VerifierSetConfirmation {
                tx_id: TransactionDigest::random().to_string().parse().unwrap(),
                event_index: 0,
                verifier_set: new_verifier_set(),
            },
        }
    }
}
