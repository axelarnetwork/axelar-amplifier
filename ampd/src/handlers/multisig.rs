use std::collections::HashMap;
use std::convert::TryFrom;

use hex::FromHex;
use multisig::types::KeyID;
use serde::de::value::MapDeserializer;
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer};

use crate::event_sub;
use crate::handlers::errors::Error;
use crate::tofnd::{MessageDigest, PublicKey};
use crate::types::TMAddress;

const EVENT_SIGNING_STARTED: &str = "wasm-signing_started";

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SigningStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    session_id: u64,
    key_id: KeyID,
    #[serde(deserialize_with = "deserialize_public_keys")]
    pub_keys: HashMap<TMAddress, PublicKey>,
    #[serde(with = "hex")]
    msg: MessageDigest,
}

fn deserialize_public_keys<'de, D>(deserializer: D) -> Result<HashMap<TMAddress, PublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let keys_by_address: HashMap<TMAddress, String> = HashMap::deserialize(deserializer)?;

    keys_by_address
        .into_iter()
        .map(|(address, hex)| {
            Ok((
                address,
                PublicKey::from_hex(hex).map_err(|err| D::Error::custom(err.to_string()))?,
            ))
        })
        .collect()
}

impl TryFrom<&event_sub::Event> for Option<SigningStartedEvent> {
    type Error = Error;

    fn try_from(event: &event_sub::Event) -> Result<Self, Self::Error> {
        match event {
            event_sub::Event::Abci { event_type, attributes } if event_type.as_str() == EVENT_SIGNING_STARTED => {
                Ok(Some(SigningStartedEvent::deserialize(MapDeserializer::new(
                    attributes.clone().into_iter(),
                ))?))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod test {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use rand::Rng;
    use std::collections::HashMap;
    use std::convert::TryInto;

    use cosmwasm_std::{Addr, HexBinary, Uint64};
    use multisig::events::Event::SigningStarted;
    use multisig::types::{MsgToSign, PublicKey};
    use tendermint::abci;

    use crate::broadcaster::key::ECDSASigningKey;

    use super::*;

    fn rand_account() -> String {
        ECDSASigningKey::random().address().to_string()
    }

    fn rand_public_key() -> PublicKey {
        let mut public_key = [0u8; 33];
        rand::thread_rng().fill(&mut public_key[..]);
        PublicKey::unchecked(HexBinary::from(public_key.as_slice()))
    }

    fn rand_message() -> HexBinary {
        let digest: [u8; 32] = rand::random();
        HexBinary::from(digest.as_slice())
    }

    fn signing_started_event() -> event_sub::Event {
        let pub_keys = (0..10)
            .map(|_| (rand_account(), rand_public_key()))
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
        event = event.add_attribute(
            "_contract_address",
            "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7",
        );

        abci::Event::new(
            event.ty,
            event
                .attributes
                .into_iter()
                .map(|cosmwasm_std::Attribute { key, value }| (STANDARD.encode(key), STANDARD.encode(value))),
        )
        .try_into()
        .unwrap()
    }

    #[test]
    fn should_not_deserialize_incorrect_event_type() {
        // incorrect event type
        let mut event: event_sub::Event = signing_started_event();
        match event {
            event_sub::Event::Abci { ref mut event_type, .. } => {
                *event_type = "incorrect".into();
            }
            _ => panic!("incorrect event type"),
        }
        let event: Option<SigningStartedEvent> = (&event).try_into().unwrap();

        assert!(event.is_none());
    }

    #[test]
    fn should_not_deserialize_invalid_pub_key() {
        let mut event = signing_started_event();

        let invalid_pub_key: [u8; 32] = rand::random();
        let mut map: HashMap<String, PublicKey> = HashMap::new();
        map.insert(
            rand_account(),
            PublicKey::unchecked(HexBinary::from(invalid_pub_key.as_slice())),
        );
        match event {
            event_sub::Event::Abci { ref mut attributes, .. } => {
                attributes.insert("pub_keys".into(), serde_json::to_value(map).unwrap());
            }
            _ => panic!("incorrect event type"),
        }

        assert!(<&event_sub::Event as TryInto<Option<SigningStartedEvent>>>::try_into(&event).is_err());
    }

    #[test]
    fn should_deserialize_event() {
        let event: Option<SigningStartedEvent> = (&signing_started_event()).try_into().unwrap();

        assert!(event.is_some());
    }
}
