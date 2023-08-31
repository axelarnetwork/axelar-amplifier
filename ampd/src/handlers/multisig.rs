use std::collections::HashMap;
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmwasm_std::{HexBinary, Uint64};
use ecdsa::VerifyingKey;
use error_stack::ResultExt;
use hex::{encode, FromHex};
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer};
use tracing::info;

use events::Error::EventTypeMismatch;
use events_derive;
use events_derive::try_from;
use multisig::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error::{self, DeserializeEvent};
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::tofnd::grpc::SharableEcdsaClient;
use crate::tofnd::MessageDigest;
use crate::types::PublicKey;
use crate::types::TMAddress;

#[derive(Debug, Deserialize)]
pub struct MultisigConfig {
    pub address: TMAddress,
}

#[derive(Debug, Deserialize)]
#[try_from("wasm-signing_started")]
struct SigningStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    session_id: u64,
    #[serde(deserialize_with = "deserialize_public_keys")]
    pub_keys: HashMap<TMAddress, PublicKey>,
    #[serde(with = "hex")]
    msg: MessageDigest,
}

fn deserialize_public_keys<'de, D>(
    deserializer: D,
) -> Result<HashMap<TMAddress, PublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let keys_by_address: HashMap<TMAddress, String> = HashMap::deserialize(deserializer)?;

    keys_by_address
        .into_iter()
        .map(|(address, hex)| {
            Ok((
                address,
                VerifyingKey::from_sec1_bytes(
                    <Vec<u8>>::from_hex(hex)
                        .map_err(D::Error::custom)?
                        .as_slice(),
                )
                .map_err(D::Error::custom)?
                .into(),
            ))
        })
        .collect()
}

pub struct Handler<B>
where
    B: BroadcasterClient,
{
    worker: TMAddress,
    multisig: TMAddress,
    broadcaster: B,
    signer: SharableEcdsaClient,
}

impl<B> Handler<B>
where
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        multisig: TMAddress,
        broadcaster: B,
        signer: SharableEcdsaClient,
    ) -> Self {
        Self {
            worker,
            multisig,
            broadcaster,
            signer,
        }
    }

    async fn broadcast_signature(
        &self,
        session_id: impl Into<Uint64>,
        signature: impl Into<HexBinary>,
    ) -> error_stack::Result<(), Error> {
        let msg = serde_json::to_vec(&ExecuteMsg::SubmitSignature {
            session_id: session_id.into(),
            signature: signature.into(),
        })
        .expect("submit signature msg should serialize");

        let tx = MsgExecuteContract {
            sender: self.worker.as_ref().clone(),
            contract: self.multisig.as_ref().clone(),
            msg,
            funds: vec![],
        };

        self.broadcaster
            .broadcast(tx)
            .await
            .change_context(Error::Broadcaster)
    }
}

#[async_trait]
impl<B> EventHandler for Handler<B>
where
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> error_stack::Result<(), Error> {
        let SigningStartedEvent {
            contract_address,
            session_id,
            pub_keys,
            msg,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(());
            }
            result => result.change_context(DeserializeEvent)?,
        };

        if self.multisig != contract_address {
            return Ok(());
        }

        info!(
            session_id = session_id,
            msg = encode(&msg),
            "get signing request",
        );

        match pub_keys.get(&self.worker) {
            Some(pub_key) => {
                let signature = self
                    .signer
                    .sign(self.multisig.to_string().as_str(), msg, pub_key)
                    .await
                    .change_context(Error::Sign)?;

                info!(signature = encode(&signature), "ready to submit signature");

                self.broadcast_signature(session_id, signature).await?;

                Ok(())
            }
            None => {
                info!("worker is not a participant");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod test {

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::collections::HashMap;
    use std::convert::{TryFrom, TryInto};
    use std::time::Duration;

    use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
    use cosmrs::{AccountId, Gas};
    use cosmwasm_std::{Addr, HexBinary, Uint64};
    use ecdsa::SigningKey;
    use error_stack::{Report, Result};
    use rand::rngs::OsRng;
    use tendermint::abci;

    use super::*;
    use crate::broadcaster::MockBroadcaster;
    use crate::queue::queued_broadcaster::{QueuedBroadcaster, QueuedBroadcasterClient};
    use crate::tofnd;
    use crate::tofnd::grpc::{MockEcdsaClient, SharableEcdsaClient};
    use crate::types;
    use multisig::events::Event::SigningStarted;
    use multisig::types::{KeyID, MsgToSign, PublicKey};

    const MULTISIG_ADDRESS: &str = "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7";

    fn rand_account() -> TMAddress {
        types::PublicKey::from(SigningKey::random(&mut OsRng).verifying_key())
            .account_id("axelar")
            .unwrap()
            .into()
    }

    fn rand_public_key() -> PublicKey {
        PublicKey::unchecked(HexBinary::from(
            types::PublicKey::from(SigningKey::random(&mut OsRng).verifying_key()).to_bytes(),
        ))
    }

    fn rand_message() -> HexBinary {
        let digest: [u8; 32] = rand::random();
        HexBinary::from(digest.as_slice())
    }

    fn signing_started_event() -> events::Event {
        let pub_keys = (0..10)
            .map(|_| (rand_account().to_string(), rand_public_key()))
            .collect::<HashMap<String, PublicKey>>();

        let poll_started = SigningStarted {
            session_id: Uint64::one(),
            key_id: KeyID {
                owner: Addr::unchecked("sender"),
                subkey: "key_id".to_string(),
            },
            pub_keys,
            msg: MsgToSign::unchecked(rand_message()),
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

    fn get_handler(
        worker: TMAddress,
        multisig: TMAddress,
        signer: SharableEcdsaClient,
    ) -> Handler<QueuedBroadcasterClient> {
        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_broadcast()
            .returning(|_| Ok(TxResponse::default()));

        let (broadcaster, _) =
            QueuedBroadcaster::new(broadcaster, Gas::default(), 100, Duration::from_secs(5));

        Handler::new(worker, multisig, broadcaster.client(), signer)
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
        let mut map: HashMap<String, PublicKey> = HashMap::new();
        map.insert(
            rand_account().to_string(),
            PublicKey::unchecked(HexBinary::from(invalid_pub_key.as_slice())),
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
        let mut client = MockEcdsaClient::new();
        client
            .expect_sign()
            .returning(move |_, _, _| Err(Report::from(tofnd::error::Error::SignFailed)));

        let handler = get_handler(
            rand_account(),
            rand_account(),
            SharableEcdsaClient::new(client),
        );

        assert!(handler.handle(&signing_started_event()).await.is_ok());
    }

    #[tokio::test]
    async fn should_not_handle_event_if_worker_is_not_a_participant() {
        let mut client = MockEcdsaClient::new();
        client
            .expect_sign()
            .returning(move |_, _, _| Err(Report::from(tofnd::error::Error::SignFailed)));

        let handler = get_handler(
            rand_account(),
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            SharableEcdsaClient::new(client),
        );

        assert!(handler.handle(&signing_started_event()).await.is_ok());
    }

    #[tokio::test]
    async fn should_not_handle_event_if_sign_failed() {
        let mut client = MockEcdsaClient::new();
        client
            .expect_sign()
            .returning(move |_, _, _| Err(Report::from(tofnd::error::Error::SignFailed)));

        let event = signing_started_event();
        let signing_started: SigningStartedEvent = ((&event).try_into() as Result<_, _>).unwrap();
        let worker = signing_started.pub_keys.keys().next().unwrap().clone();
        let handler = get_handler(
            worker,
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            SharableEcdsaClient::new(client),
        );

        assert!(matches!(
            *handler.handle(&event).await.unwrap_err().current_context(),
            Error::Sign
        ));
    }
}
