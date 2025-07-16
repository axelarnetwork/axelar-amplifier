use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::try_from;
use events::Error::EventTypeMismatch;
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tonlib_core::TonAddress;
use tracing::{info, info_span};
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::ton::rpc::TonClient;
use crate::ton::verifier::verify_verifier_set;
use crate::types::TMAddress;

type Result<T> = error_stack::Result<T, Error>;

use crate::handlers::ton_verify_msg::hex_tx_hash_string;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    #[serde(with = "hex_tx_hash_string")]
    pub message_id: HexTxHash,
    pub verifier_set: VerifierSet,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: TonAddress,
    expires_at: u64,
    participants: Vec<TMAddress>,
}

pub struct Handler<C>
where
    C: TonClient,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C> Handler<C>
where
    C: TonClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
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
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: TonClient + Send + Sync,
{
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

        let vote = info_span!(
            "verify a new verifier set for an EVM chain",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            id = verifier_set.message_id.to_string()
        )
        .in_scope(|| async {
            info!("ready to verify a new verifier set in poll");

            let log = self
                .rpc_client
                .get_log(&source_gateway_address, &verifier_set.message_id)
                .await;
            if log.is_err() {
                return Vote::NotFound;
            }
            let log = log.unwrap();

            match verify_verifier_set(log, &verifier_set) {
                true => Vote::SucceededOnChain,
                false => Vote::NotFound,
            }
        });

        Ok(vec![self
            .vote_msg(poll_id, vote.await)
            .into_any()
            .expect("vote msg should serialize")])
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use axelar_wasm_std::msg_id::HexTxHash;
    use ethers_core::types::H256;
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::handlers::ton_verify_verifier_set::PollStartedEvent;
    use crate::ton::rpc::TonRpcClient;
    use crate::types::TMAddress;
    use crate::PREFIX;

    #[test]
    fn ton_verify_verifier_set_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: Result<PollStartedEvent, _> = event.try_into();

        assert!(event.is_ok());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let rpc_client = TonRpcClient::new("invalid");

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier, rpc_client, rx);

        // poll is not expired yet, should get one no vote
        let result = handler.handle(&event).await.unwrap();
        assert_eq!(result.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired, should not get a vote
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_id = HexTxHash::new(H256::repeat_byte(1));
        PollStarted::VerifierSet {
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                tx_id: msg_id.tx_hash_as_hex_no_prefix(),
                event_index: 0u32,
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "ethereum".parse().unwrap(),
                source_gateway_address: "kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH"
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
