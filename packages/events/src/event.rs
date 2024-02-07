use axelar_wasm_std::FnExt;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use error_stack::{Report, Result, ResultExt};
use serde_json::Value;
use tendermint::abci::EventAttribute;
use tendermint::{abci, block};

use crate::errors::DecodingError;
use crate::Error;

use cosmrs::AccountId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    BlockBegin(block::Height),
    BlockEnd(block::Height),
    Abci {
        event_type: String,
        attributes: serde_json::Map<String, serde_json::Value>,
    },
}

impl Event {
    pub fn block_begin(height: impl Into<block::Height>) -> Self {
        Event::BlockBegin(height.into())
    }

    pub fn block_end(height: impl Into<block::Height>) -> Self {
        Event::BlockEnd(height.into())
    }
}

impl TryFrom<abci::Event> for Event {
    type Error = Report<Error>;

    fn try_from(event: abci::Event) -> Result<Self, Error> {
        let abci::Event {
            kind: event_type,
            attributes,
        } = event;

        let attributes = attributes
            .iter()
            .map(try_into_kv_pair)
            .collect::<Result<_, _>>()?;

        Ok(Self::Abci {
            event_type,
            attributes,
        })
    }
}

fn try_into_kv_pair(attr: &EventAttribute) -> Result<(String, Value), Error> {
    decode_event_attribute(attr)
        .change_context(Error::DecodingAttributesFailed)
        .map(|(key, value)| {
            (
                key,
                serde_json::from_str(&value).unwrap_or_else(|_| value.into()),
            )
        })
}

fn decode_event_attribute(attribute: &EventAttribute) -> Result<(String, String), DecodingError> {
    Ok((
        base64_to_utf8(&attribute.key)?,
        base64_to_utf8(&attribute.value)?,
    ))
}

fn base64_to_utf8(base64_str: &str) -> std::result::Result<String, DecodingError> {
    Ok(STANDARD.decode(base64_str)?.then(String::from_utf8)?)
}

pub fn get_contract_address(event: &Event) -> Option<AccountId> {
    let contract_address = match event {
        Event::Abci {
            event_type: _,
            attributes,
        } => {
            if let Some(address) = attributes.get("_contract_address") {
                return serde_json::from_value::<AccountId>(address.clone()).ok();
            }
            None
        }
        _ => None,
    };
    contract_address
}

pub fn event_is_from_contract(event: &Event, contract_address: &AccountId) -> bool {
    match get_contract_address(event) {
        Some(address) => &address == contract_address,
        _ => false,
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use cosmrs::AccountId;

    use crate::{event_is_from_contract, get_contract_address, Event};

    fn make_event_with_contract_address(contract_address: &AccountId) -> Event {
        let mut attributes = serde_json::Map::new();
        attributes.insert(
            "_contract_address".to_string(),
            contract_address.to_string().into(),
        );
        Event::Abci {
            event_type: "some_event".to_string(),
            attributes,
        }
    }

    #[test]
    fn should_get_contract_address_if_exists() {
        let expected_contract_address =
            AccountId::from_str("axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7").unwrap();

        let event = make_event_with_contract_address(&expected_contract_address);

        let contract_address = get_contract_address(&event);
        assert!(contract_address.is_some());
        assert_eq!(contract_address.unwrap(), expected_contract_address);
    }

    #[test]
    fn should_not_get_contract_address_if_not_exists() {
        let event = Event::Abci {
            event_type: "some_event".to_string(),
            attributes: serde_json::Map::new(),
        };
        let contract_address = get_contract_address(&event);
        assert!(contract_address.is_none());
    }

    #[test]
    fn event_is_from_contract_should_return_true_iff_contract_address_matches() {
        let contract_address =
            AccountId::from_str("axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7").unwrap();
        let event = make_event_with_contract_address(&contract_address);
        assert!(event_is_from_contract(&event, &contract_address));

        let diff_contract_address =
            AccountId::from_str("axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6").unwrap();
        assert!(!event_is_from_contract(&event, &diff_contract_address));
    }

    #[test]
    fn event_is_from_contract_should_return_false_if_contract_address_does_not_exist() {
        let contract_address =
            AccountId::from_str("axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7").unwrap();

        let event_without_contract_address = Event::Abci {
            event_type: "some_event".to_string(),
            attributes: serde_json::Map::new(),
        };

        assert!(!event_is_from_contract(
            &event_without_contract_address,
            &contract_address
        ));
    }
}
