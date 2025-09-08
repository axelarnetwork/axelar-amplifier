use std::str::FromStr as _;

use aleo_gateway_types::SignersRotated;
use async_trait::async_trait;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use events::Error::EventTypeMismatch;
use events::{try_from, Event};
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;
use serde::Deserialize;
use snarkvm::prelude::{Address, Network, ProgramID};
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use voting_verifier::msg::ExecuteMsg;

use crate::aleo::http_client::ClientTrait as AleoClientTrait;
use crate::aleo::verifier::verify_verifier_set;
use crate::aleo::{Receipt, ReceiptBuilder};
use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::types::TMAddress;

#[derive(Deserialize, Debug)]
#[serde(bound = "Address<N>: for<'a> Deserialize<'a>")]
pub struct VerifierSetConfirmation<N: Network> {
    pub message_id: N::TransitionID,
    pub verifier_set: VerifierSet,
}

type AleoProgram = String;

#[derive(Deserialize, Debug)]
#[serde(bound = "VerifierSetConfirmation<N>: for<'a> Deserialize<'a>")]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent<N>
where
    N: Network,
{
    verifier_set: VerifierSetConfirmation<N>,
    poll_id: PollId,
    source_chain: ChainName,
    #[allow(dead_code)]
    source_gateway_address: AleoProgram,
    expires_at: u64,
    #[allow(dead_code)]
    confirmation_height: u64,
    participants: Vec<TMAddress>,
}

#[derive(Clone)]
pub struct Handler<N: Network, C: AleoClientTrait<N>> {
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    http_client: C,
    latest_block_height: Receiver<u64>,
    chain: ChainName,
    verifier_set_contract: ProgramID<N>,
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
        verifier_set_contract: String,
    ) -> Result<Self, crate::aleo::error::Error> {
        Ok(Self {
            verifier,
            voting_verifier_contract,
            http_client: aleo_client,
            latest_block_height,
            chain,
            verifier_set_contract: ProgramID::from_str(&verifier_set_contract)?,
        })
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

async fn fetch_transition_receipt<N, C>(
    http_client: &C,
    program: &ProgramID<N>,
    id: N::TransitionID,
) -> (N::TransitionID, Receipt<N, SignersRotated<N>>)
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
            .check_signer_rotation()
    }
    .await;

    match receipt {
        Ok(receipt) => (id.to_owned(), receipt),
        Err(e) => (id, Receipt::NotFound(id, e)),
    }
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
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            verifier_set,
            poll_id,
            source_chain,
            source_gateway_address: _,
            expires_at,
            confirmation_height: _,
            participants,
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

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        // Transition IDs on Aleo chain
        let transition: N::TransitionID = verifier_set.message_id;

        let (_, receipt) = fetch_transition_receipt::<N, C>(
            &self.http_client,
            &self.verifier_set_contract,
            transition,
        )
        .await;

        let poll_id_str: String = poll_id.into();
        let source_chain_str: String = source_chain.into();
        let vote = info_span!(
            "verify messages from an Aleo chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            message_ids = transition.to_string(),
        )
        .in_scope(|| {
            info!("ready to verify messages in poll");

            let vote = verify_verifier_set(&receipt, &verifier_set);
            info!(
                vote = ?vote,
                "ready to vote for messages in poll"
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
    use std::convert::TryInto;
    use std::str::FromStr;

    use axelar_wasm_std::voting::PollId;
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{aleo_schnorr_test_data, build_verifier_set};
    use multisig::verifier_set::VerifierSet;
    use router_api::ChainName;
    use snarkvm::prelude::Network;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use crate::handlers::aleo_verify_verifier_set::PollStartedEvent;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::types::TMAddress;
    use crate::PREFIX;

    type CurrentNetwork = snarkvm::prelude::TestnetV0;

    #[test]
    fn aleo_verify_verifier_set_should_deserialize_correct_event() {
        let expiration = 100u64;
        let config: Config<CurrentNetwork> = config(None, expiration);

        let event: Event =
            into_structured_event(poll_started_event(&config), &TMAddress::random(PREFIX));
        let event: PollStartedEvent<CurrentNetwork> = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    struct Config<N: Network> {
        transition: N::TransitionID,
        verifier_set: VerifierSet,
        poll_id: PollId,
        source_chain: ChainName,
        source_gateway_address: String,
        confirmation_height: u64,
        expires_at: u64,
        participants: Vec<TMAddress>,
    }

    fn config<N: Network>(verifier: Option<TMAddress>, expires_at: u64) -> Config<N> {
        let Ok(transition) = N::TransitionID::from_str(
            "au17kdp7a7p6xuq6h0z3qrdydn4f6fjaufvzvlgkdd6vzpr87lgcgrq8qx6st",
        ) else {
            panic!("Failed to parse transition ID")
        };
        let key_type = KeyType::AleoSchnorr;
        let verifier_set = build_verifier_set(key_type, &aleo_schnorr_test_data::signers());
        let poll_id = PollId::from_str("100").unwrap();
        let source_chain = ChainName::from_str("aleo-2").unwrap();
        let source_gateway_address = "mygateway.aleo".to_string();
        let confirmation_height = 15;
        let participants = participants(5, verifier);

        Config {
            transition,
            verifier_set,
            poll_id,
            source_chain,
            source_gateway_address,
            confirmation_height,
            expires_at,
            participants,
        }
    }

    fn poll_started_event<N: Network>(config: &Config<N>) -> PollStarted {
        PollStarted::VerifierSet {
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                tx_id: "foo".to_string().parse().unwrap(), // this field is deprecated
                event_index: 0u32, // this field is deprecated
                message_id: config.transition.to_string().parse().unwrap(),
                verifier_set: config.verifier_set.clone(),
            },
            metadata: PollMetadata {
                poll_id: config.poll_id,
                source_chain: config.source_chain.clone(),
                source_gateway_address: config.source_gateway_address.parse().unwrap(),
                confirmation_height: config.confirmation_height,
                expires_at: config.expires_at,
                participants: config.participants.iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),

            },
        }
    }
}
