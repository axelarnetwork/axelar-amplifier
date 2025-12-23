use std::collections::HashMap;

use ampd::types::{PublicKey, TMAddress};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::types::{Key, KeyAlgorithm};
use ampd_sdk::grpc::client::EventHandlerClient;
use ampd_sdk::runtime::HandlerRuntime;
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
use xrpl_types::types::XRPLAccountId;

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
    pub fn new(runtime: &HandlerRuntime, chain_name: ChainName) -> Self {
        Self::builder()
            .verifier(runtime.verifier.clone().into())
            .multisig(runtime.contracts.multisig.clone().into())
            .chain(chain_name)
            .build()
    }

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
            chain: _chain,
        } = event;

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
                let pub_key_hex = HexBinary::from(pub_key.to_bytes());
                let multisig_pub_key = multisig::key::PublicKey::try_from((
                    multisig::key::KeyType::Ecdsa,
                    pub_key_hex,
                ))
                .change_context(Error::PublicKey)?;

                let xrpl_address = XRPLAccountId::from(&multisig_pub_key);

                let msg_digest =
                    xrpl_types::types::message_to_sign(msg.as_ref().to_vec(), &xrpl_address)
                        .change_context(Error::MessageToSign)?;

                let data = <nonempty::Vec<u8>>::try_from(msg_digest.to_vec())
                    .change_context(Error::MessageToSign)?;
                let key_id = TryInto::<nonempty::String>::try_into(self.multisig.to_string())
                    .change_context(Error::KeyId)?;

                let signature = client
                    .sign(
                        Some(Key {
                            id: key_id,
                            algorithm: KeyAlgorithm::Ecdsa,
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
        let attributes = HashMap::from([(
            "chain".to_string(),
            serde_json::Value::String(self.chain.to_string()),
        )]);

        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: SigningStartedEvent::event_type(),
                contract: self.multisig.clone().into(),
                attributes,
            }],
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ampd::types::TMAddress;
    use ampd_handlers::test_utils::into_structured_event;
    use ampd_sdk::grpc;
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::{chain_name, nonempty};
    use cosmrs::AccountId;
    use cosmwasm_std::{HexBinary, Uint64};
    use error_stack::bail;
    use multisig::events::Event;
    use multisig::key::PublicKey;
    use multisig::types::MsgToSign;
    use rand::rngs::OsRng;
    use tokio::test as async_test;

    use super::{EventHandler, Handler, SigningStartedEvent};
    use crate::error::Error;

    const PREFIX: &str = "axelar";
    const MULTISIG_ADDRESS: &str = "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7";

    fn rand_public_key() -> PublicKey {
        PublicKey::Ecdsa(HexBinary::from(
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

    fn signing_started_event(expires_at: u64) -> events::Event {
        let pub_keys = (0..10)
            .map(|_| (TMAddress::random(PREFIX).to_string(), rand_public_key()))
            .collect::<HashMap<String, PublicKey>>();

        let poll_started = Event::SigningStarted {
            session_id: Uint64::one(),
            verifier_set_id: "verifier_set_id".to_string(),
            pub_keys,
            msg: MsgToSign::unchecked(rand_message()),
            chain_name: chain_name!("xrpl"),
            expires_at,
        };

        into_structured_event(poll_started, &TMAddress::random(PREFIX))
    }

    fn mock_handler_client(latest_block_height: u64) -> MockHandlerTaskClient {
        let mut client = MockHandlerTaskClient::new();
        client
            .expect_latest_block_height()
            .returning(move || Ok(latest_block_height));
        // Mock the sign method to return a dummy signature
        client
            .expect_sign()
            .returning(|_, _| Ok(nonempty::Vec::try_from(vec![1u8; 64]).unwrap()));
        client
    }

    #[test]
    fn should_deserialize_event() {
        let event: error_stack::Result<SigningStartedEvent, events::Error> =
            (&signing_started_event(100)).try_into();

        assert!(event.is_ok());
    }

    #[async_test]
    async fn should_not_handle_event_if_verifier_is_not_a_participant() {
        let expiration = 100u64;
        let mut client = mock_handler_client(expiration - 1);

        let event = signing_started_event(expiration);
        let handler = Handler::builder()
            .verifier(TMAddress::random(PREFIX))
            .multisig(TMAddress::from(
                MULTISIG_ADDRESS.parse::<AccountId>().unwrap(),
            ))
            .chain(chain_name!("xrpl"))
            .build();

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();

        assert_eq!(res, vec![]);
    }

    #[async_test]
    async fn should_not_handle_event_if_sign_failed() {
        let expiration = 100u64;
        let mut client = MockHandlerTaskClient::new();
        client
            .expect_latest_block_height()
            .returning(move || Ok(99));
        client.expect_sign().returning(|_, _| {
            bail!(grpc::error::Error::App(
                grpc::error::AppError::InvalidByteArray
            ))
        });

        let event = signing_started_event(expiration);
        let signing_started: SigningStartedEvent = ((&event).try_into() as Result<_, _>).unwrap();
        let verifier = signing_started.pub_keys.keys().next().unwrap().clone();
        let handler = Handler::builder()
            .verifier(verifier)
            .multisig(TMAddress::from(
                MULTISIG_ADDRESS.parse::<AccountId>().unwrap(),
            ))
            .chain(chain_name!("xrpl"))
            .build();

        assert!(matches!(
            handler
                .handle(event.try_into().unwrap(), &mut client)
                .await
                .unwrap_err()
                .current_context(),
            Error::Sign
        ));
    }

    #[async_test]
    async fn should_skip_expired_session() {
        let expiration = 100u64;
        let mut client = mock_handler_client(expiration + 1);

        let event = signing_started_event(expiration);
        let signing_started: SigningStartedEvent = ((&event).try_into() as Result<_, _>).unwrap();
        let verifier = signing_started.pub_keys.keys().next().unwrap().clone();
        let handler = Handler::builder()
            .verifier(verifier)
            .multisig(TMAddress::from(
                MULTISIG_ADDRESS.parse::<AccountId>().unwrap(),
            ))
            .chain(chain_name!("xrpl"))
            .build();

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();

        assert_eq!(res, vec![]);
    }
}
