use std::fmt::Display;

use axelar_wasm_std::FnExt;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cosmrs::AccountId;
use error_stack::{Report, Result, ResultExt};
use tendermint::abci::EventAttribute;
use tendermint::{abci, block};

use crate::errors::DecodingError;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    BlockBegin(block::Height),
    BlockEnd(block::Height),
    Abci {
        event_type: String,
        attributes: serde_json::Map<String, serde_json::Value>,
    },
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::BlockBegin(height) => write!(f, "BlockBegin({})", height),
            Event::BlockEnd(height) => write!(f, "BlockEnd({})", height),
            Event::Abci {
                event_type,
                attributes,
            } => write!(
                f,
                "Abci {{ event_type: {}, attributes: {} }}",
                event_type,
                serde_json::to_string(attributes).expect("event attributes must be serializable")
            ),
        }
    }
}

impl Event {
    pub fn block_begin(height: impl Into<block::Height>) -> Self {
        Event::BlockBegin(height.into())
    }

    pub fn block_end(height: impl Into<block::Height>) -> Self {
        Event::BlockEnd(height.into())
    }

    pub fn is_from_contract(&self, from_address: &AccountId) -> bool {
        match self.contract_address() {
            Some(emitting_address) => &emitting_address == from_address,
            _ => false,
        }
    }

    fn contract_address(&self) -> Option<AccountId> {
        match self {
            Event::Abci {
                event_type: _,
                attributes,
            } => attributes
                .get("_contract_address")
                .and_then(|address| serde_json::from_value::<AccountId>(address.clone()).ok()),
            _ => None,
        }
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

fn try_into_kv_pair(attr: &EventAttribute) -> Result<(String, serde_json::Value), Error> {
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

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use cosmrs::AccountId;

    use crate::Event;

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

        let contract_address = event.contract_address();
        assert_eq!(contract_address, Some(expected_contract_address));
    }

    #[test]
    fn should_not_get_contract_address_if_not_exists() {
        let event = Event::Abci {
            event_type: "some_event".to_string(),
            attributes: serde_json::Map::new(),
        };
        let contract_address = event.contract_address();
        assert!(contract_address.is_none());
    }

    #[test]
    fn event_is_from_contract_should_return_true_iff_contract_address_matches() {
        let contract_address =
            AccountId::from_str("axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7").unwrap();
        let event = make_event_with_contract_address(&contract_address);
        assert!(event.is_from_contract(&contract_address));

        let diff_contract_address =
            AccountId::from_str("axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6").unwrap();
        assert!(!event.is_from_contract(&diff_contract_address));
    }

    #[test]
    fn event_is_from_contract_should_return_false_if_contract_address_does_not_exist() {
        let contract_address =
            AccountId::from_str("axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7").unwrap();

        let event_without_contract_address = Event::Abci {
            event_type: "some_event".to_string(),
            attributes: serde_json::Map::new(),
        };

        assert!(!event_without_contract_address.is_from_contract(&contract_address));
    }
}
