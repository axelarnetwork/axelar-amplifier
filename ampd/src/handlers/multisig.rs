use std::collections::HashMap;
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use cosmwasm_std::{HexBinary, Uint64};
use ecdsa::VerifyingKey;
use error_stack::{Report, ResultExt};
use events_derive;
use events_derive::try_from;
use hex::encode;
use multisig::msg::ExecuteMsg;
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer};
use tokio::sync::watch::Receiver;
use tracing::info;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error::{self, DeserializeEvent};
use crate::tofnd::grpc::Multisig;
use crate::tofnd::{self, MessageDigest};
use crate::types::{PublicKey, TMAddress};

#[derive(Debug, Deserialize)]
#[try_from("wasm-signing_started")]
struct SigningStartedEvent {
    session_id: u64,
    #[serde(deserialize_with = "deserialize_public_keys")]
    pub_keys: HashMap<TMAddress, PublicKey>,
    #[serde(with = "hex")]
    msg: MessageDigest,
    expires_at: u64,
}

fn deserialize_public_keys<'de, D>(
    deserializer: D,
) -> Result<HashMap<TMAddress, PublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let keys_by_address: HashMap<TMAddress, multisig::key::PublicKey> =
        HashMap::deserialize(deserializer)?;

    keys_by_address
        .into_iter()
        .map(|(address, pk)| match pk {
            multisig::key::PublicKey::Ecdsa(hex) => Ok((
                address,
                VerifyingKey::from_sec1_bytes(hex.as_ref())
                    .map_err(D::Error::custom)?
                    .into(),
            )),

            multisig::key::PublicKey::Ed25519(hex) => {
                let pk: cosmrs::tendermint::PublicKey =
                    cosmrs::tendermint::crypto::ed25519::VerificationKey::try_from(hex.as_ref())
                        .map_err(D::Error::custom)?
                        .into();
                Ok((address, pk.into()))
            }
        })
        .collect()
}

pub struct Handler<S> {
    verifier: TMAddress,
    multisig: TMAddress,
    signer: S,
    latest_block_height: Receiver<u64>,
}

impl<S> Handler<S>
where
    S: Multisig,
{
    pub fn new(
        verifier: TMAddress,
        multisig: TMAddress,
        signer: S,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            multisig,
            signer,
            latest_block_height,
        }
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
impl<S> EventHandler for Handler<S>
where
    S: Multisig + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> error_stack::Result<Vec<Any>, Error> {
        if !event.is_from_contract(self.multisig.as_ref()) {
            return Ok(vec![]);
        }

        let SigningStartedEvent {
            session_id,
            pub_keys,
            msg,
            expires_at,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report)
                if matches!(
                    report.current_context(),
                    events::Error::EventTypeMismatch(_)
                ) =>
            {
                return Ok(vec![]);
            }
            result => result.change_context(DeserializeEvent)?,
        };

        info!(
            session_id = session_id,
            msg = encode(&msg),
            "get signing request",
        );

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(
                session_id = session_id.to_string(),
                "skipping expired signing session"
            );
            return Ok(vec![]);
        }

        match pub_keys.get(&self.verifier) {
            Some(pub_key) => {
                let key_type = match pub_key.type_url() {
                    PublicKey::ED25519_TYPE_URL => tofnd::Algorithm::Ed25519,
                    PublicKey::SECP256K1_TYPE_URL => tofnd::Algorithm::Ecdsa,
                    unspported => return Err(Report::from(Error::KeyType(unspported.to_string()))),
                };

                let signature = self
                    .signer
                    .sign(
                        self.multisig.to_string().as_str(),
                        msg.clone(),
                        pub_key,
                        key_type,
                    )
                    .await
                    .change_context(Error::Sign)?;

                info!(signature = encode(&signature), "ready to submit signature");

                Ok(vec![self
                    .submit_signature_msg(session_id, signature)
                    .into_any()
                    .expect("submit signature msg should serialize")])
            }
            None => {
                info!("verifier is not a participant");

                Ok(vec![])
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::convert::{TryFrom, TryInto};

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
    use cosmrs::AccountId;
    use cosmwasm_std::{HexBinary, Uint64};
    use ecdsa::SigningKey;
    use error_stack::{Report, Result};
    use multisig::events::Event;
    use multisig::types::MsgToSign;
    use rand::distributions::Alphanumeric;
    use rand::rngs::OsRng;
    use rand::Rng;
    use router_api::ChainName;
    use tendermint::abci;
    use tokio::sync::watch;

    use super::*;
    use crate::broadcaster::MockBroadcaster;
    use crate::tofnd::grpc::MockMultisig;
    use crate::{tofnd, types};

    const MULTISIG_ADDRESS: &str = "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7";

    fn rand_account() -> TMAddress {
        types::PublicKey::from(SigningKey::random(&mut OsRng).verifying_key())
            .account_id("axelar")
            .unwrap()
            .into()
    }

    fn rand_public_key() -> multisig::key::PublicKey {
        multisig::key::PublicKey::Ecdsa(HexBinary::from(
            types::PublicKey::from(SigningKey::random(&mut OsRng).verifying_key()).to_bytes(),
        ))
    }

    fn rand_message() -> HexBinary {
        let digest: [u8; 32] = rand::random();
        HexBinary::from(digest.as_slice())
    }

    fn rand_chain_name() -> ChainName {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect::<String>()
            .try_into()
            .unwrap()
    }

    fn signing_started_event() -> events::Event {
        let pub_keys = (0..10)
            .map(|_| (rand_account().to_string(), rand_public_key()))
            .collect::<HashMap<String, multisig::key::PublicKey>>();

        let poll_started = Event::SigningStarted {
            session_id: Uint64::one(),
            verifier_set_id: "verifier_set_id".to_string(),
            pub_keys,
            msg: MsgToSign::unchecked(rand_message()),
            chain_name: rand_chain_name(),
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

    // this returns an event that is named SigningStarted, but some expected fields are missing
    fn signing_started_event_with_missing_fields(contract_address: &str) -> events::Event {
        let pub_keys = (0..10)
            .map(|_| (rand_account().to_string(), rand_public_key()))
            .collect::<HashMap<String, multisig::key::PublicKey>>();

        let poll_started = Event::SigningStarted {
            session_id: Uint64::one(),
            verifier_set_id: "verifier_set_id".to_string(),
            pub_keys,
            msg: MsgToSign::unchecked(rand_message()),
            chain_name: rand_chain_name(),
            expires_at: 100u64,
        };

        let mut event: cosmwasm_std::Event = poll_started.into();
        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute("_contract_address", contract_address);
        event.attributes.retain(|attr| attr.key != "expires_at");

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

    fn handler(
        verifier: TMAddress,
        multisig: TMAddress,
        signer: MockMultisig,
        latest_block_height: u64,
    ) -> Handler<MockMultisig> {
        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_broadcast()
            .returning(|_| Ok(TxResponse::default()));

        let (_, rx) = watch::channel(latest_block_height);

        Handler::new(verifier, multisig, signer, rx)
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
            rand_account().to_string(),
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
    async fn should_not_handle_event_with_missing_fields_if_multisig_address_does_not_match() {
        let client = MockMultisig::default();

        let handler = handler(
            rand_account(),
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            client,
            100u64,
        );

        assert_eq!(
            handler
                .handle(&signing_started_event_with_missing_fields(
                    &rand_account().to_string()
                ))
                .await
                .unwrap(),
            vec![]
        );
    }

    #[tokio::test]
    async fn should_error_on_event_with_missing_fields_if_multisig_address_does_match() {
        let client = MockMultisig::default();

        let handler = handler(
            rand_account(),
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            client,
            100u64,
        );

        assert!(handler
            .handle(&signing_started_event_with_missing_fields(MULTISIG_ADDRESS))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn should_not_handle_event_if_multisig_address_does_not_match() {
        let client = MockMultisig::default();

        let handler = handler(rand_account(), rand_account(), client, 100u64);

        assert_eq!(
            handler.handle(&signing_started_event()).await.unwrap(),
            vec![]
        );
    }

    #[tokio::test]
    async fn should_not_handle_event_if_verifier_is_not_a_participant() {
        let mut client = MockMultisig::default();
        client
            .expect_sign()
            .returning(move |_, _, _, _| Err(Report::from(tofnd::error::Error::SignFailed)));

        let handler = handler(
            rand_account(),
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            client,
            100u64,
        );

        assert_eq!(
            handler.handle(&signing_started_event()).await.unwrap(),
            vec![]
        );
    }

    #[tokio::test]
    async fn should_not_handle_event_if_sign_failed() {
        let mut client = MockMultisig::default();
        client
            .expect_sign()
            .returning(move |_, _, _, _| Err(Report::from(tofnd::error::Error::SignFailed)));

        let event = signing_started_event();
        let signing_started: SigningStartedEvent = ((&event).try_into() as Result<_, _>).unwrap();
        let verifier = signing_started.pub_keys.keys().next().unwrap().clone();
        let handler = handler(
            verifier,
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            client,
            99u64,
        );

        assert!(matches!(
            *handler.handle(&event).await.unwrap_err().current_context(),
            Error::Sign
        ));
    }

    #[tokio::test]
    async fn should_not_handle_event_if_session_expired() {
        let mut client = MockMultisig::default();
        client
            .expect_sign()
            .returning(move |_, _, _, _| Err(Report::from(tofnd::error::Error::SignFailed)));

        let event = signing_started_event();
        let signing_started: SigningStartedEvent = ((&event).try_into() as Result<_, _>).unwrap();
        let verifier = signing_started.pub_keys.keys().next().unwrap().clone();
        let handler = handler(
            verifier,
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            client,
            101u64,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }
}
