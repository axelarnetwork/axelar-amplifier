use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::{tx::Msg, Any};
use error_stack::ResultExt;
use ethers::types::{TransactionReceipt, U64};
use multisig::verifier_set::VerifierSet;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;

use axelar_wasm_std::{
    msg_id::tx_hash_event_index::HexTxHashAndEventIndex,
    voting::{PollId, Vote},
};
use events::Error::EventTypeMismatch;
use events_derive::try_from;
use router_api::ChainName;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::evm::finalizer::Finalization;
use crate::evm::verifier::verify_worker_set;
use crate::evm::{finalizer, json_rpc::EthereumClient};
use crate::handlers::errors::Error;
use crate::types::{EVMAddress, Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub tx_id: Hash,
    pub event_index: u32,
    pub verifier_set: VerifierSet,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: router_api::ChainName,
    source_gateway_address: EVMAddress,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<TMAddress>,
}

pub struct Handler<C>
where
    C: EthereumClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    chain: ChainName,
    finalizer_type: Finalization,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        chain: ChainName,
        finalizer_type: Finalization,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            chain,
            finalizer_type,
            rpc_client,
            latest_block_height,
        }
    }

    async fn finalized_tx_receipt(
        &self,
        tx_hash: Hash,
        confirmation_height: u64,
    ) -> Result<Option<TransactionReceipt>> {
        let latest_finalized_block_height =
            finalizer::pick(&self.finalizer_type, &self.rpc_client, confirmation_height)
                .latest_finalized_block_height()
                .await
                .change_context(Error::Finalizer)?;
        let tx_receipt = self
            .rpc_client
            .transaction_receipt(tx_hash)
            .await
            .change_context(Error::Finalizer)?;

        Ok(tx_receipt.and_then(|tx_receipt| {
            if tx_receipt
                .block_number
                .unwrap_or(U64::MAX)
                .le(&latest_finalized_block_height)
            {
                Some(tx_receipt)
            } else {
                None
            }
        }))
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
    C: EthereumClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            expires_at,
            confirmation_height,
            participants,
            verifier_set,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if self.chain != source_chain {
            return Ok(vec![]);
        }

        if !participants.contains(&self.worker) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let tx_receipt = self
            .finalized_tx_receipt(verifier_set.tx_id, confirmation_height)
            .await?;
        let vote = info_span!(
            "verify a new worker set for an EVM chain",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            id = HexTxHashAndEventIndex::new(verifier_set.tx_id, verifier_set.event_index)
                .to_string()
        )
        .in_scope(|| {
            info!("ready to verify a new worker set in poll");

            let vote = tx_receipt.map_or(Vote::NotFound, |tx_receipt| {
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
    use std::{collections::BTreeMap, convert::TryInto, str::FromStr};

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use error_stack::{Report, Result};
    use ethers::providers::ProviderError;
    use multisig::{key::PublicKey, msg::Signer, verifier_set::VerifierSet};
    use tendermint::abci;
    use tokio::{sync::watch, test as async_test};

    use events::Event;
    use router_api::ChainName;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use crate::{
        event_processor::EventHandler,
        evm::{finalizer::Finalization, json_rpc::MockEthereumClient},
        handlers::evm_verify_verifier_set::{self, PollStartedEvent},
        types::{EVMAddress, Hash, TMAddress},
        PREFIX,
    };

    #[test]
    fn should_deserialize_correct_event() {
        let event: Event = get_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: Result<PollStartedEvent, events::Error> = event.try_into();

        assert!(event.is_ok());
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
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = get_event(
            poll_started_event(participants(5, Some(worker.clone())), expiration),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = evm_verify_verifier_set::Handler::new(
            worker,
            voting_verifier,
            ChainName::from_str("ethereum").unwrap(),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            rx,
        );

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
    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        PollStarted::VerifierSet {
            verifier_set: VerifierSetConfirmation {
                tx_id: format!("0x{:x}", Hash::random()).parse().unwrap(),
                event_index: 100,
                verifier_set: new_verifier_set(),
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "ethereum".parse().unwrap(),
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

    fn get_event(event: impl Into<cosmwasm_std::Event>, contract_address: &TMAddress) -> Event {
        let mut event: cosmwasm_std::Event = event.into();

        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute("_contract_address", contract_address.to_string());

        abci::Event::new(
            event.ty,
            event
                .attributes
                .into_iter()
                .map(|cosmwasm_std::Attribute { key, value }| {
                    (STANDARD.encode(key), STANDARD.encode(value))
                }),
        )
        .try_into()
        .unwrap()
    }

    fn participants(n: u8, worker: Option<TMAddress>) -> Vec<TMAddress> {
        (0..n)
            .map(|_| TMAddress::random(PREFIX))
            .chain(worker)
            .collect()
    }
}
