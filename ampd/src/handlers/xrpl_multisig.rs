use std::collections::HashMap;
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use cosmwasm_std::{HexBinary, Uint64};
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events_derive;
use events_derive::try_from;
use hex::encode;
use multisig::{ExecuteMsg, MsgToSign};
use router_api::ChainName;
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer};
use tokio::sync::watch::Receiver;
use tracing::info;
use xrpl_types::types::XRPLAccountId;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error::{self, DeserializeEvent};
use crate::tofnd::grpc::Multisig;
use crate::tofnd::{Algorithm, MessageDigest};
use crate::types::{PublicKey, TMAddress};

#[derive(Debug, Deserialize)]
#[try_from("wasm-signing_started")]
struct SigningStartedEvent {
    session_id: u64,
    #[serde(deserialize_with = "deserialize_public_keys")]
    pub_keys: HashMap<TMAddress, PublicKey>,
    msg: MsgToSign,
    expires_at: u64,
    chain: ChainName,
}

fn deserialize_public_keys<'de, D>(
    deserializer: D,
) -> Result<HashMap<TMAddress, PublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let keys_by_address: HashMap<TMAddress, multisig::PublicKey> =
        HashMap::deserialize(deserializer)?;

    keys_by_address
        .into_iter()
        .map(|(address, pk)| Ok((address, pk.try_into().map_err(D::Error::custom)?)))
        .collect()
}

pub struct Handler<S> {
    verifier: TMAddress,
    multisig: TMAddress,
    chain: ChainName,
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
        chain: ChainName,
        signer: S,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            multisig,
            chain,
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
            chain,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![]);
            }
            result => result.change_context(DeserializeEvent)?,
        };

        if !chain.eq(&self.chain) {
            return Ok(vec![]);
        }

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
            Some(&pub_key) => {
                let pub_key_hex = HexBinary::from(pub_key.to_bytes());
                let multisig_pub_key =
                    multisig::PublicKey::try_from((multisig::KeyType::Ecdsa, pub_key_hex))
                        .map_err(|_e| Error::PublicKey)?;
                let xrpl_address = XRPLAccountId::from(&multisig_pub_key);

                let msg_digest = MessageDigest::from(
                    xrpl_types::types::message_to_sign(msg.as_ref().to_vec(), &xrpl_address)
                        .map_err(|_e| Error::MessageToSign)?,
                );

                let signature = self
                    .signer
                    .sign(
                        self.multisig.to_string().as_str(),
                        msg_digest,
                        pub_key,
                        Algorithm::Ecdsa,
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
    use error_stack::{Report, Result};
    use multisig::events::Event;
    use multisig::key::PublicKey;
    use multisig::types::MsgToSign;
    use rand::rngs::OsRng;
    use router_api::ChainName;
    use tendermint::abci;
    use tokio::sync::watch;

    use super::*;
    use crate::broadcaster::MockBroadcaster;
    use crate::tofnd;
    use crate::tofnd::grpc::MockMultisig;

    const MULTISIG_ADDRESS: &str = "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7";
    const PREFIX: &str = "axelar";

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
            chain_name: "xrpl".parse().unwrap(),
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

    fn handler(
        verifier: TMAddress,
        multisig: TMAddress,
        chain: ChainName,
        signer: MockMultisig,
        latest_block_height: u64,
    ) -> Handler<MockMultisig> {
        let mut broadcaster = MockBroadcaster::new();
        broadcaster
            .expect_broadcast()
            .returning(|_| Ok(TxResponse::default()));

        let (_, rx) = watch::channel(latest_block_height);

        Handler::new(verifier, multisig, chain, signer, rx)
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
            TMAddress::random(PREFIX).to_string(),
            PublicKey::Ecdsa(HexBinary::from(invalid_pub_key.as_slice())),
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
        let client = MockMultisig::default();

        let handler = handler(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            "xrpl".parse().unwrap(),
            client,
            100u64,
        );

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
            TMAddress::random(PREFIX),
            TMAddress::from(MULTISIG_ADDRESS.parse::<AccountId>().unwrap()),
            "xrpl".parse().unwrap(),
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
            "xrpl".parse().unwrap(),
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
            "xrpl".parse().unwrap(),
            client,
            101u64,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[tokio::test]
    async fn should_not_handle_event_if_chain_does_not_match() {
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
            "not-xrpl".parse().unwrap(),
            client,
            100u64,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }
}
