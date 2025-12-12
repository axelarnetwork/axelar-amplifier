use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;

use ampd::handlers::solana_verify_msg::Message;
use ampd::handlers::solana_verify_verifier_set::VerifierSetConfirmation;
use ampd::monitoring;
use ampd::solana::msg_verifier::verify_message;
use ampd::solana::verifier_set_verifier::verify_verifier_set;
use ampd::solana::{SolanaRpcClientProxy, SolanaTransaction};
use ampd_handlers::voting::{self, Error, PollEventData as _, VotingHandler};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::AccountId;
use error_stack::{Report, ResultExt};
use events::{try_from, Event, EventType};
use serde::Deserialize;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use typed_builder::TypedBuilder;

pub type Result<T> = error_stack::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-messages_poll_started")]
pub struct MessagesPollStarted {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: String,
    confirmation_height: u64,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<AccountId>,
}

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-verifier_set_poll_started")]
pub struct VerifierSetPollStarted {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: String,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<AccountId>,
}

#[derive(Clone, Debug)]
pub enum PollEventData {
    Message(Message),
    VerifierSet(VerifierSetConfirmation),
}

impl voting::PollEventData for PollEventData {
    type Digest = Signature;
    type MessageId = Base58SolanaTxSignatureAndEventIndex;
    type ChainAddress = Pubkey;
    type Receipt = SolanaTransaction;

    fn tx_hash(&self) -> Self::Digest {
        match self {
            PollEventData::Message(message) => message.message_id.raw_signature.into(),
            PollEventData::VerifierSet(verifier_set) => {
                verifier_set.message_id.raw_signature.into()
            }
        }
    }

    fn message_id(&self) -> &Self::MessageId {
        match self {
            PollEventData::Message(message) => &message.message_id,
            PollEventData::VerifierSet(verifier_set) => &verifier_set.message_id,
        }
    }

    fn verify(&self, source_gateway_address: &Pubkey, tx_receipt: &SolanaTransaction) -> Vote {
        match self {
            PollEventData::Message(message) => {
                verify_message(tx_receipt, message, source_gateway_address)
            }
            PollEventData::VerifierSet(verifier_set) => {
                // TODO: fix domain_separator
                let domain_separator: [u8; 32] = [42; 32];

                verify_verifier_set(
                    tx_receipt,
                    verifier_set,
                    &domain_separator,
                    source_gateway_address,
                )
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum PollStartedEvent {
    Messages(MessagesPollStarted),
    VerifierSet(VerifierSetPollStarted),
}

impl TryFrom<Event> for PollStartedEvent {
    type Error = Report<events::Error>;

    fn try_from(event: Event) -> std::result::Result<Self, Self::Error> {
        if let Ok(event) = MessagesPollStarted::try_from(event.clone()) {
            Ok(PollStartedEvent::Messages(event))
        } else if let Ok(event) = VerifierSetPollStarted::try_from(event.clone()) {
            Ok(PollStartedEvent::VerifierSet(event))
        } else {
            Err(events::Error::EventTypeMismatch(format!(
                "{}/{}",
                MessagesPollStarted::event_type(),
                VerifierSetPollStarted::event_type()
            )))
            .attach_printable(format!("{{ event = {event:?} }}"))
        }
    }
}

impl From<PollStartedEvent> for voting::PollStartedEvent<PollEventData, Pubkey> {
    fn from(event: PollStartedEvent) -> Self {
        match event {
            PollStartedEvent::Messages(message_event) => voting::PollStartedEvent {
                poll_data: message_event
                    .messages
                    .into_iter()
                    .map(PollEventData::Message)
                    .collect(),
                poll_id: message_event.poll_id,
                source_chain: message_event.source_chain,
                source_gateway_address: message_event.source_gateway_address.parse().unwrap(),
                expires_at: message_event.expires_at,
                confirmation_height: message_event.confirmation_height,
                participants: message_event.participants,
            },
            PollStartedEvent::VerifierSet(verifier_set_event) => voting::PollStartedEvent {
                poll_data: vec![PollEventData::VerifierSet(verifier_set_event.verifier_set)],
                poll_id: verifier_set_event.poll_id,
                source_chain: verifier_set_event.source_chain,
                source_gateway_address: verifier_set_event.source_gateway_address.parse().unwrap(),
                expires_at: verifier_set_event.expires_at,
                confirmation_height: verifier_set_event.confirmation_height,
                participants: verifier_set_event.participants,
            },
        }
    }
}

#[allow(dead_code)]
#[derive(TypedBuilder)]
pub struct Handler<C>
where
    C: SolanaRpcClientProxy,
{
    pub verifier: AccountId,
    pub voting_verifier_contract: AccountId,
    pub chain: ChainName,
    pub gateway_address: Pubkey,
    // #[allow(dead_code)] TODO: fix domain separator
    pub domain_separator: [u8; 32],
    pub rpc_client: C,
    pub monitoring_client: monitoring::Client,
}

#[async_trait]
impl<C> VotingHandler for Handler<C>
where
    C: SolanaRpcClientProxy + Send + Sync,
{
    type Digest = Signature;
    type Receipt = SolanaTransaction;
    type ChainAddress = Pubkey;
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
        let tx_calls = poll_data.iter().map(|data| async {
            let signature = data.tx_hash();
            self.rpc_client
                .tx(&signature)
                .await
                .map(|tx| (signature, tx))
        });

        let finalized_tx_receipts: HashMap<Signature, SolanaTransaction> =
            futures::future::join_all(tx_calls)
                .await
                .into_iter()
                .flatten()
                .collect::<HashMap<Signature, SolanaTransaction>>();

        Ok(finalized_tx_receipts)
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: SolanaRpcClientProxy + Send + Sync,
{
    type Err = Error;
    type Event = PollStartedEvent;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        event: PollStartedEvent,
        client: &mut HC,
    ) -> Result<Vec<cosmrs::Any>> {
        VotingHandler::handle(self, event.into(), client).await
    }

    fn subscription_params(&self) -> SubscriptionParams {
        use events::AbciEventTypeFilter;

        SubscriptionParams::new(
            vec![
                AbciEventTypeFilter {
                    event_type: MessagesPollStarted::event_type(),
                    contract: self.voting_verifier_contract.clone(),
                    attributes: Default::default(),
                },
                AbciEventTypeFilter {
                    event_type: VerifierSetPollStarted::event_type(),
                    contract: self.voting_verifier_contract.clone(),
                    attributes: Default::default(),
                },
            ],
            false,
        )
    }
}

impl<C> Debug for Handler<C>
where
    C: SolanaRpcClientProxy + Send + Sync,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handler")
            .field("verifier", &self.verifier)
            .field("voting_verifier_contract", &self.voting_verifier_contract)
            .field("gateway_address", &self.gateway_address)
            .field("rpc_client", &"WARN: Solana sdk does impl Debug")
            .field("monitoring_client", &self.monitoring_client)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use ampd::handlers::test_utils::{into_structured_event, participants};
    use ampd::monitoring::{metrics, test_utils};
    use ampd::solana::Client;
    use ampd::types::{Hash, TMAddress};
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::chain_name;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use router_api::address;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use tokio::test as async_test;
    use voting_verifier::events::{
        PollMetadata, PollStarted, TxEventConfirmation, VerifierSetConfirmation
    };

    use super::{
        Handler, EventHandler, PollStartedEvent, Pubkey,
        Signature, SolanaRpcClientProxy, SolanaTransaction, Vote,
    };

    const PREFIX: &str = "axelar";

    fn message_poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let signature_1 = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP";
        let inner_ix_group_index_1 = 1_u32;
        let inner_ix_index_1 = 10_u32;
        let message_id_1 = format!("{signature_1}-{inner_ix_group_index_1}.{inner_ix_index_1}");

        let signature_2 = "41SgBTfsWbkdixDdVNESM6YmDAzEcKEubGPkaXmtTVUd2EhMaqPEy3qh5ReTtTb4Le4F16SSBFjQCxkekamNrFNT";
        let inner_ix_group_index_2 = 2_u32;
        let inner_ix_index_2 = 88_u32;
        let message_id_2 = format!("{signature_2}-{inner_ix_group_index_2}.{inner_ix_index_2}");

        let source_gateway_address = axelar_solana_gateway::ID;

        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!("solana"),
                source_gateway_address: source_gateway_address.to_string().parse().unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            #[allow(deprecated)]
            messages: vec![
                TxEventConfirmation {
                    source_address: Pubkey::from_str(
                        "9Tp4XJZLQKdM82BHYfNAG6V3RWpLC7Y5mXo1UqKZFTJ3",
                    )
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                    message_id: message_id_1.parse().unwrap(),
                    destination_chain: chain_name!("ethereum"),
                    destination_address: address!("0x3ad1f33ef5814e7adb43ed7fb39f9b45053ecab1"),
                    payload_hash: Hash::from_slice(&[1; 32]).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    source_address: Pubkey::from_str(
                        "H1QLZVpX7B4WMNY5UqKZG3RFTJ9M82BXoLQF26TJCY5N",
                    )
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                    message_id: message_id_2.parse().unwrap(),
                    destination_chain: chain_name!("ethereum"),
                    destination_address: address!("0x3ad1f33ef5814e7adb43ed7fb39f9b45053ecab2"),
                    payload_hash: Hash::from_slice(&[2; 32]).to_fixed_bytes(),
                },
            ],
        }
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let signature_1 = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP";
        let inner_ix_group_index_1 = 1_u32;
        let inner_ix_index_1 = 10_u32;
        let message_id_1 = format!("{signature_1}-{inner_ix_group_index_1}.{inner_ix_index_1}");
        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!("solana"),
                source_gateway_address: axelar_solana_gateway::ID.to_string().parse().unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            verifier_set: VerifierSetConfirmation {
                message_id: message_id_1
                    .to_string()
                    .try_into()
                    .unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
        }
    }

    struct ValidResponseSolanaRpc;
    #[async_trait::async_trait]
    impl SolanaRpcClientProxy for ValidResponseSolanaRpc {
        async fn tx(&self, signature: &Signature) -> Option<SolanaTransaction> {
            Some(SolanaTransaction {
                signature: *signature,
                inner_instructions: vec![],
                err: None,
                account_keys: vec![axelar_solana_gateway::ID], // Gateway program at index 0
            })
        }

        async fn domain_separator(&self, _gateway_address: &Pubkey) -> Option<[u8; 32]> {
            unimplemented!()
        }
    }

    fn mock_rpc_client() -> RpcClient {
        let mocks = HashMap::new();
        RpcClient::new_mock_with_mocks("http://mock.example".to_string(), mocks)
    }

    fn mock_handler_client(latest_block_height: u64) -> MockHandlerTaskClient {
        let mut client = MockHandlerTaskClient::new();
        client
            .expect_latest_block_height()
            .returning(move || Ok(latest_block_height));
        client
    }

    #[test]
    fn solana_verify_msg_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            message_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(event);
    }

    #[test]
    fn solana_verify_verifier_set_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(event);
    }

    // Should not handle event if it is not emitted from voting verifier
    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let gateway_address = axelar_solana_gateway::ID;
        let domain_separator: [u8; 32] = [42; 32];
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            message_poll_started_event(participants(5, None), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let rpc_client = Client::new(
            mock_rpc_client(),
            monitoring_client.clone(),
            chain_name!("solana"),
        );

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("solana"))
            .rpc_client(rpc_client)
            .gateway_address(gateway_address)
            .domain_separator(domain_separator)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();

        assert_eq!(res, vec![]);
    }

    // Should not handle event if source gateway address doesn't match configured gateway
    #[async_test]
    #[should_panic]
    async fn should_fail_message_poll_with_mismatched_gateway_address() {
        let gateway_address = axelar_solana_gateway::ID;
        let domain_separator: [u8; 32] = [42; 32];
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        // Create an event with a different gateway address
        let mut event_data = message_poll_started_event(participants(5, Some(verifier.clone())), 100);
        if let PollStarted::Messages {
            ref mut metadata, ..
        } = event_data
        {
            // Use a different gateway address
            metadata.source_gateway_address = "1111111111111111111111111111111111111111111".parse().unwrap();
        }

        let event = into_structured_event(event_data, &voting_verifier);

        let (monitoring_client, _) = test_utils::monitoring_client();

        let rpc_client = Client::new(
            mock_rpc_client(),
            monitoring_client.clone(),
            chain_name!("solana"),
        );

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("solana"))
            .rpc_client(rpc_client)
            .gateway_address(gateway_address)
            .domain_separator(domain_separator)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        // Expected panic: 'event does not match event type 
        // `wasm-messages_poll_started/wasm-verifier_set_poll_started`
        // due to gateway address mismatch'
        handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();
    }

    // Should not handle event if source gateway address doesn't match configured gateway
    #[async_test]
    #[should_panic]
    async fn should_fail_verifier_poll_with_mismatched_gateway_address() {
        let gateway_address = axelar_solana_gateway::ID;
        let domain_separator: [u8; 32] = [42; 32];
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        // Create an event with a different gateway address
        let mut event_data = verifier_set_poll_started_event(participants(5, Some(verifier.clone())), 100);
        if let PollStarted::VerifierSet {
            ref mut metadata, ..
        } = event_data
        {
            // Use a different gateway address
            metadata.source_gateway_address = "1111111111111111111111111111111111111111111".parse().unwrap();
        }

        let event = into_structured_event(event_data, &voting_verifier);

        let (monitoring_client, _) = test_utils::monitoring_client();

        let rpc_client = Client::new(
            mock_rpc_client(),
            monitoring_client.clone(),
            chain_name!("solana"),
        );

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("solana"))
            .rpc_client(rpc_client)
            .gateway_address(gateway_address)
            .domain_separator(domain_separator)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        // Expected panic: 'event does not match event type 
        // `wasm-messages_poll_started/wasm-verifier_set_poll_started`
        // due to gateway address mismatch'
        handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();
    }

    #[async_test]
    async fn should_vote_correctly_in_message_poll() {
        let gateway_address = axelar_solana_gateway::ID;
        let domain_separator: [u8; 32] = [42; 32];
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("solana"))
            .rpc_client(ValidResponseSolanaRpc)
            .gateway_address(gateway_address)
            .domain_separator(domain_separator)
            .monitoring_client(monitoring_client)
            .build();
        
        let mut client = mock_handler_client(expiration - 1);

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();

        assert_eq!(res.len(), 1);
        assert!(MsgExecuteContract::from_any(res.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_vote_correctly_in_verifier_poll() {
        let gateway_address = axelar_solana_gateway::ID;
        let domain_separator: [u8; 32] = [42; 32];
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("solana"))
            .rpc_client(ValidResponseSolanaRpc)
            .gateway_address(gateway_address)
            .domain_separator(domain_separator)
            .monitoring_client(monitoring_client)
            .build();
        
        let mut client = mock_handler_client(expiration - 1);

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();

        assert_eq!(res.len(), 1);
        assert!(MsgExecuteContract::from_any(res.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_record_message_verification_vote_metric() {
        let solana_chain_name = chain_name!("solana");
        let gateway_address = axelar_solana_gateway::ID;
        let domain_separator: [u8; 32] = [42; 32];
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(solana_chain_name.clone())
            .rpc_client(ValidResponseSolanaRpc)
            .gateway_address(gateway_address)
            .domain_separator(domain_separator)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await;
        assert!(res.is_ok());

        for _ in 0..2 {
            let msg = receiver.recv().await.unwrap();
            assert_eq!(
                msg,
                metrics::Msg::VerificationVote {
                    vote_decision: Vote::NotFound,
                    chain_name: solana_chain_name.clone(),
                }
            );
        }
        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_record_verifier_set_verification_vote_metric() {
        let solana_chain_name = chain_name!("solana");
        let gateway_address = axelar_solana_gateway::ID;
        let domain_separator: [u8; 32] = [42; 32];
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(solana_chain_name.clone())
            .rpc_client(ValidResponseSolanaRpc)
            .gateway_address(gateway_address)
            .domain_separator(domain_separator)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await;
        assert!(res.is_ok());

        let metric = receiver.recv().await.unwrap();

        assert_eq!(
            metric,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: solana_chain_name,
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_skip_expired_message_poll() {
        let gateway_address = axelar_solana_gateway::ID;
        let domain_separator: [u8; 32] = [42; 32];
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("solana"))
            .rpc_client(ValidResponseSolanaRpc)
            .gateway_address(gateway_address)
            .domain_separator(domain_separator)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);


        // poll is not expired yet, should hit proxy
        let res = handler
            .handle(event.clone().try_into().unwrap(), &mut client)
            .await
            .unwrap();
        assert_eq!(res.len(), 1);

        let mut client = mock_handler_client(expiration + 1);

        // poll is expired
        assert_eq!(
            handler
                .handle(event.try_into().unwrap(), &mut client)
                .await
                .unwrap(),
            vec![]
        );
    }

    #[async_test]
    async fn should_skip_expired_verifier_poll() {
        let gateway_address = axelar_solana_gateway::ID;
        let domain_separator: [u8; 32] = [42; 32];
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("solana"))
            .rpc_client(ValidResponseSolanaRpc)
            .gateway_address(gateway_address)
            .domain_separator(domain_separator)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);


        // poll is not expired yet, should hit proxy
        let res = handler
            .handle(event.clone().try_into().unwrap(), &mut client)
            .await
            .unwrap();
        assert_eq!(res.len(), 1);

        let mut client = mock_handler_client(expiration + 1);

        // poll is expired
        assert_eq!(
            handler
                .handle(event.try_into().unwrap(), &mut client)
                .await
                .unwrap(),
            vec![]
        );
    }
}
