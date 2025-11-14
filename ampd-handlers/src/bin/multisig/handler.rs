use std::collections::HashMap;

use ampd::types::{PublicKey, TMAddress};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::types::{Key, KeyAlgorithm};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::nonempty;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use cosmwasm_std::{HexBinary, Uint64};
use error_stack::ResultExt;
use events::{try_from, AbciEventTypeFilter, EventType};
use hex::encode;
use multisig::msg::ExecuteMsg;
use multisig::types::MsgToSign;
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer};
use tracing::info;
use typed_builder::TypedBuilder;

use crate::error::Error;

pub type Result<T> = error_stack::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-signing_started")]
pub struct SigningStartedEvent {
    session_id: u64,
    #[serde(deserialize_with = "deserialize_public_keys")]
    pub_keys: HashMap<TMAddress, PublicKey>,
    msg: MsgToSign,
    expires_at: u64,
    chain: ChainName,
}

fn deserialize_public_keys<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<TMAddress, PublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let keys_by_address: HashMap<TMAddress, multisig::key::PublicKey> =
        HashMap::deserialize(deserializer)?;

    keys_by_address
        .into_iter()
        .map(|(address, pk)| Ok((address, pk.try_into().map_err(D::Error::custom)?)))
        .collect()
}

#[derive(Debug, TypedBuilder)]
pub struct Handler {
    pub verifier: TMAddress,
    pub multisig: TMAddress,
    pub chain: ChainName,
}

impl Handler {
    fn submit_signature_msg(
        &self,
        session_id: impl Into<Uint64>,
        signature: impl Into<HexBinary>,
    ) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.multisig.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::SubmitSignature {
                session_id: session_id.into(),
                signature: signature.into(),
            })
            .expect("submit signature msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    type Err = Error;
    type Event = SigningStartedEvent;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        event: SigningStartedEvent,
        client: &mut HC,
    ) -> Result<Vec<Any>> {
        let SigningStartedEvent {
            session_id,
            pub_keys,
            msg,
            expires_at,
            chain,
        } = event;

        if !chain.eq(&self.chain) {
            info!(
                chain = chain.to_string(),
                handler_chain = self.chain.to_string(),
                "chain mismatch, skipping event"
            );
            return Ok(vec![]);
        }

        let latest_block_height = client
            .latest_block_height()
            .await
            .change_context(Error::EventHandling)?;

        if latest_block_height >= expires_at {
            info!(
                session_id = session_id.to_string(),
                "skipping expired signing session"
            );
            return Ok(vec![]);
        }

        info!(
            session_id = session_id,
            msg = encode(&msg),
            "received signing request",
        );

        match pub_keys.get(&self.verifier) {
            Some(pub_key) => {
                let key_type = match pub_key {
                    PublicKey::Secp256k1(_) => KeyAlgorithm::Ecdsa,
                    PublicKey::Ed25519(_) => KeyAlgorithm::Ed25519,
                };

                let data = <nonempty::Vec<u8>>::try_from(msg.as_ref().to_vec())
                    .change_context(Error::MessageToSign)?;
                let key_id = TryInto::<nonempty::String>::try_into(self.multisig.to_string())
                    .change_context(Error::KeyId)?;

                let signature = client
                    .sign(
                        Some(Key {
                            id: key_id,
                            algorithm: key_type,
                        }),
                        data,
                    )
                    .await
                    .change_context(Error::Sign)?;

                info!(
                    signature = encode(signature.as_slice()),
                    "ready to submit signature"
                );

                Ok(vec![self
                    .submit_signature_msg(session_id, signature.as_slice())
                    .into_any()
                    .expect("submit signature msg should serialize")])
            }
            None => {
                info!("verifier is not a participant");

                Ok(vec![])
            }
        }
    }

    fn subscription_params(&self) -> SubscriptionParams {
        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: SigningStartedEvent::event_type(),
                contract: self.multisig.clone().into(),
            }],
            false,
        )
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::convert::{TryFrom, TryInto};

    use ampd_sdk::grpc;
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::chain_name;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmrs::AccountId;
    use cosmwasm_std::{HexBinary, Uint64};
    use error_stack::{Report, Result};
    use multisig::events::Event;
    use multisig::types::MsgToSign;
    use rand::rngs::OsRng;
    use tendermint::abci;

    use super::*;

    const MULTISIG_ADDRESS: &str = "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7";
    const PREFIX: &str = "axelar";
    const ETHEREUM: &str = "Ethereum";

    fn rand_public_key() -> multisig::key::PublicKey {
        multisig::key::PublicKey::Ecdsa(HexBinary::from(
            k256::ecdsa::SigningKey::random(&mut OsRng)
                .verifying_key()
                .to_sec1_bytes()
                .to_vec(),
        ))
    }

    fn rand_message() -> HexBinary {
        let digest: [u8; 32] = rand::random();
        HexBinary::from(digest.as_slice())
    }

    fn signing_started_event() -> events::Event {
        let pub_keys = (0..10)
            .map(|_| (TMAddress::random(PREFIX).to_string(), rand_public_key()))
            .collect::<HashMap<String, multisig::key::PublicKey>>();

        let poll_started = Event::SigningStarted {
            session_id: Uint64::one(),
            verifier_set_id: "verifier_set_id".to_string(),
            pub_keys,
            msg: MsgToSign::unchecked(rand_message()),
            chain_name: chain_name!(ETHEREUM),
            expires_at: 100u64,
        };

        let mut event: cosmwasm_std::Event = poll_started.into();
        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute("_contract_address", MULTISIG_ADDRESS);

        events::Event::try_from(abci::Event::new(
            event.ty,
            event
                .attributes
                .into_iter()
                .map(|cosmwasm_std::Attribute { key, value }| {
                    (STANDARD.encode(key), STANDARD.encode(value))
                }),
        ))
        .unwrap()
    }

    fn handler(verifier: TMAddress, multisig: TMAddress, chain: ChainName) -> Handler {
        Handler::builder()
            .verifier(verifier)
            .multisig(multisig)
            .chain(chain)
            .build()
    }

    fn mock_handler_client(latest_block_height: u64) -> MockHandlerTaskClient {
        let mut client = MockHandlerTaskClient::new();
        client
            .expect_latest_block_height()
            .returning(move || Ok(latest_block_height));
        client
    }

    #[test]
    fn should_not_deserialize_incorrect_event_type() {
        // incorrect event type
        let mut event: events::Event = signing_started_event();
        match event {
            events::Event::Abci {
                ref mut event_type, ..
            } => {
                *event_type = "incorrect".into();
            }
            _ => panic!("incorrect event type"),
        }
        let event: Result<SigningStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            events::Error::EventTypeMismatch(_)
        ));
    }

    #[test]
    fn should_not_deserialize_invalid_pub_key() {
        let mut event = signing_started_event();

        let invalid_pub_key: [u8; 32] = rand::random();
        let mut map: HashMap<String, multisig::key::PublicKey> = HashMap::new();
        map.insert(
            TMAddress::random(PREFIX).to_string(),
            multisig::key::PublicKey::Ecdsa(HexBinary::from(invalid_pub_key.as_slice())),
        );
        match event {
            events::Event::Abci {
                ref mut attributes, ..
            } => {
                attributes.insert("pub_keys".into(), serde_json::to_value(map).unwrap());
            }
            _ => panic!("incorrect event type"),
        }

        let event: Result<SigningStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            events::Error::DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn should_deserialize_event() {
        let event: Result<SigningStartedEvent, events::Error> =
            (&signing_started_event()).try_into();

        assert!(event.is_ok());
    }

    #[tokio::test]
    async fn should_not_handle_event_if_multisig_address_does_not_match() {
        let handler = handler(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            chain_name!(ETHEREUM),
        );

        assert_eq!(
            handler
                .handle(
                    signing_started_event().try_into().unwrap(),
                    &mut mock_handler_client(100)
                )
                .await
                .unwrap(),
            vec![]
        );
    }

    #[tokio::test]
    async fn should_not_handle_event_if_verifier_is_not_a_participant() {
        let handler = handler(
            TMAddress::random(PREFIX),
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            chain_name!(ETHEREUM),
        );

        assert_eq!(
            handler
                .handle(
                    signing_started_event().try_into().unwrap(),
                    &mut mock_handler_client(100)
                )
                .await
                .unwrap(),
            vec![]
        );
    }

    #[tokio::test]
    async fn should_not_handle_event_if_sign_failed() {
        let mut client = mock_handler_client(99);
        client.expect_sign().returning(move |_, _| {
            Err(Report::from(grpc::error::Error::Grpc(
                grpc::error::GrpcError::ServiceUnavailable(
                    "signing service unavailable".to_string(),
                ),
            )))
        });

        let event = signing_started_event();
        let signing_started: SigningStartedEvent = ((&event).try_into() as Result<_, _>).unwrap();
        let verifier = signing_started.pub_keys.keys().next().unwrap().clone();
        let handler = handler(
            verifier,
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            chain_name!(ETHEREUM),
        );

        assert!(matches!(
            *handler
                .handle(event.try_into().unwrap(), &mut client)
                .await
                .unwrap_err()
                .current_context(),
            Error::Sign
        ));
    }

    #[tokio::test]
    async fn should_not_handle_event_if_session_expired() {
        let mut client = mock_handler_client(101);
        client.expect_sign().returning(move |_, _| {
            Err(Report::from(grpc::error::Error::Grpc(
                grpc::error::GrpcError::ServiceUnavailable(
                    "signing service unavailable".to_string(),
                ),
            )))
        });

        let event = signing_started_event();
        let signing_started: SigningStartedEvent = ((&event).try_into() as Result<_, _>).unwrap();
        let verifier = signing_started.pub_keys.keys().next().unwrap().clone();
        let handler = handler(
            verifier,
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            chain_name!(ETHEREUM),
        );

        assert_eq!(
            handler
                .handle(event.try_into().unwrap(), &mut client)
                .await
                .unwrap(),
            vec![]
        );
    }

    #[tokio::test]
    async fn should_not_handle_event_for_different_chain() {
        let mut client = mock_handler_client(100);
        client.expect_sign().returning(move |_, _| {
            Err(Report::from(grpc::error::Error::Grpc(
                grpc::error::GrpcError::ServiceUnavailable(
                    "signing service unavailable".to_string(),
                ),
            )))
        });

        let event = signing_started_event();
        let signing_started: SigningStartedEvent = ((&event).try_into() as Result<_, _>).unwrap();
        let verifier = signing_started.pub_keys.keys().next().unwrap().clone();
        let handler = handler(
            verifier,
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            chain_name!("wrong-chain-name"),
        );

        assert_eq!(
            handler
                .handle(event.try_into().unwrap(), &mut mock_handler_client(100))
                .await
                .unwrap(),
            vec![]
        );
    }
}
