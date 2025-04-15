use std::collections::{BTreeMap, HashMap};
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

pub struct AbciEventTypeFilter {
    pub event_type: String,
}

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
            } => {
                let sorted_map: BTreeMap<_, _> = attributes.iter().collect();

                write!(
                    f,
                    "Abci {{ event_type: {}, attributes: {} }}",
                    event_type,
                    serde_json::to_string(&sorted_map).expect("attributes must be serializable")
                )
            }
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

    pub fn contract_address(&self) -> Option<AccountId> {
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

impl TryFrom<ampd_proto::subscribe_response::Event> for Event {
    type Error = Report<Error>;

    fn try_from(event: ampd_proto::subscribe_response::Event) -> Result<Event, Error> {
        match event {
            ampd_proto::subscribe_response::Event::BlockBegin(block_start) => {
                block::Height::try_from(block_start.height)
                    .change_context_lazy(|| Error::BlockHeightConversion {
                        block_height: block_start.height,
                    })
                    .map(Self::BlockBegin)
            }
            ampd_proto::subscribe_response::Event::BlockEnd(block_end) => {
                block::Height::try_from(block_end.height)
                    .change_context_lazy(|| Error::BlockHeightConversion {
                        block_height: block_end.height,
                    })
                    .map(Self::BlockEnd)
            }
            ampd_proto::subscribe_response::Event::Abci(abci) => Ok(Self::Abci {
                event_type: abci.r#type,
                attributes: convert_attributes(&abci.attributes),
            }),
        }
    }
}

fn convert_attributes(
    proto_attrs: &HashMap<String, String>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut result = serde_json::Map::new();

    for (key, value) in proto_attrs {
        let json_value = serde_json::from_str(value)
            .unwrap_or_else(|_| serde_json::Value::String(value.clone()));

        result.insert(key.clone(), json_value);
    }

    result
}

impl From<Event> for ampd_proto::Event {
    fn from(event: Event) -> Self {
        let contract_address = if let Event::Abci { .. } = &event {
            event
                .contract_address()
                .map(|addr| addr.to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };

        let (event_type, attributes) = match event {
            Event::BlockBegin(_) | Event::BlockEnd(_) => {
                let type_name = if matches!(event, Event::BlockBegin(_)) {
                    "block_begin"
                } else {
                    "block_end"
                };
                (type_name.to_string(), HashMap::new())
            }
            Event::Abci {
                event_type,
                attributes,
            } => (
                event_type,
                attributes
                    .into_iter()
                    .map(|(key, value)| (key, value.to_string()))
                    .collect(),
            ),
        };

        Self {
            r#type: event_type,
            contract: contract_address,
            attributes,
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::str::FromStr;

    use cosmrs::AccountId;
    use tendermint::block;

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

    fn create_and_check_proto_event_with_type(event: Event, expected_type: &str) {
        let converted_proto = ampd_proto::Event::from(event);

        assert_eq!(converted_proto.r#type, expected_type);
        assert!(converted_proto.attributes.is_empty());
        assert_eq!(converted_proto.contract, "");
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

    #[test]
    fn block_begin_event_conversion_should_succeed() {
        let height: u64 = 12345;
        let proto_event =
            ampd_proto::subscribe_response::Event::BlockBegin(ampd_proto::EventBlockBegin {
                height,
            });

        let domain_event_response = Event::try_from(proto_event);
        assert!(domain_event_response.is_ok());
        let domain_event = domain_event_response.unwrap();

        assert!(
            matches!(domain_event, Event::BlockBegin(h) if h == block::Height::try_from(height).unwrap())
        );

        create_and_check_proto_event_with_type(domain_event, "block_begin");
    }

    #[test]
    fn block_end_event_conversion_should_succeed() {
        let height: u64 = 54321;
        let proto_event =
            ampd_proto::subscribe_response::Event::BlockEnd(ampd_proto::EventBlockEnd { height });

        let domain_event_response = Event::try_from(proto_event);
        assert!(domain_event_response.is_ok());
        let domain_event = domain_event_response.unwrap();

        assert!(
            matches!(domain_event, Event::BlockEnd(h) if h == block::Height::try_from(height).unwrap())
        );

        create_and_check_proto_event_with_type(domain_event, "block_end");
    }

    #[test]
    fn abci_event_conversion_should_succeed() {
        let contract_address_string =
            "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7".to_string();

        let mut attrs = HashMap::new();
        attrs.insert("key1".to_string(), "value1".to_string());
        attrs.insert("key2".to_string(), "42".to_string());
        attrs.insert(
            "_contract_address".to_string(),
            contract_address_string.clone(),
        );

        let proto_event = ampd_proto::subscribe_response::Event::Abci(ampd_proto::Event {
            r#type: "test_event".to_string(),
            contract: contract_address_string.clone(),
            attributes: attrs,
        });

        let domain_event_response = Event::try_from(proto_event.clone());
        assert!(domain_event_response.is_ok());
        let domain_event = domain_event_response.unwrap();

        goldie::assert!(&domain_event.to_string());

        let converted_proto = ampd_proto::Event::from(domain_event);
        assert_eq!(converted_proto.r#type, "test_event");
        assert_eq!(converted_proto.contract, contract_address_string,);
        assert_eq!(
            converted_proto.attributes.get("key1").unwrap(),
            "\"value1\""
        );
        assert_eq!(converted_proto.attributes.get("key2").unwrap(), "42");
    }

    #[test]
    fn invalid_block_height_conversion_should_fail() {
        let max_height: u64 = u64::MAX;
        let proto_event =
            ampd_proto::subscribe_response::Event::BlockBegin(ampd_proto::EventBlockBegin {
                height: max_height,
            });

        let result = Event::try_from(proto_event);
        assert!(result.is_err());

        goldie::assert!(&result.unwrap_err().to_string());
    }
}
