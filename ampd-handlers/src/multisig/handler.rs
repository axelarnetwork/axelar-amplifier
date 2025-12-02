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

use super::error::Error;

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
