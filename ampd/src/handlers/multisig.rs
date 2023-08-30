use std::collections::HashMap;

use ecdsa::VerifyingKey;
use hex::FromHex;
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer};

use events_derive;
use multisig::types::KeyID;

use crate::tofnd::MessageDigest;
use crate::types::PublicKey;
use crate::types::TMAddress;
use events_derive::try_from;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[try_from("wasm-signing_started")]
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

#[cfg(test)]
mod test {
    use error_stack::Result;
    use std::collections::HashMap;
    use std::convert::{TryFrom, TryInto};

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmwasm_std::{Addr, HexBinary, Uint64};
    use tendermint::abci;

    use multisig::events::Event::SigningStarted;
    use multisig::types::{MsgToSign, PublicKey};

    use crate::broadcaster::key::ECDSASigningKey;

    use super::*;

    fn rand_account() -> String {
        ECDSASigningKey::random().address().to_string()
    }

    fn rand_public_key() -> PublicKey {
        PublicKey::unchecked(HexBinary::from(
            ECDSASigningKey::random().public_key().to_bytes(),
        ))
    }

    fn rand_message() -> HexBinary {
        let digest: [u8; 32] = rand::random();
        HexBinary::from(digest.as_slice())
    }

    fn signing_started_event() -> events::Event {
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
            rand_account(),
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
}
