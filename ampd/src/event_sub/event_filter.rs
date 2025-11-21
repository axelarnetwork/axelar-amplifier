use std::collections::HashMap;

use axelar_wasm_std::nonempty;
use error_stack::{report, Report, Result, ResultExt};
use thiserror::Error;

use crate::types::{AxelarAddress, TMAddress};

#[derive(Error, Debug)]
pub enum Error {
    #[error("empty filter")]
    EmptyFilter,
    #[error("invalid contract address {0}")]
    InvalidContractAddress(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventFilter {
    event_type: Option<nonempty::String>,
    contract: Option<TMAddress>,
    attributes: HashMap<String, serde_json::Value>,
}

impl TryFrom<ampd_proto::EventFilter> for EventFilter {
    type Error = Report<Error>;

    fn try_from(event_filter: ampd_proto::EventFilter) -> Result<Self, Error> {
        let event_type = event_filter.r#type.try_into().ok();
        let contract = if event_filter.contract.is_empty() {
            None
        } else {
            let contract = event_filter
                .contract
                .parse::<AxelarAddress>()
                .change_context(Error::InvalidContractAddress(event_filter.contract))?;

            Some(contract.into()) // TODO: change to AxelarAddress
        };
        let attributes: HashMap<_, _> = event_filter
            .attributes
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    serde_json::from_str(&value).unwrap_or(serde_json::Value::String(value)),
                )
            })
            .collect();

        if event_type.is_none() && contract.is_none() && attributes.is_empty() {
            return Err(report!(Error::EmptyFilter));
        }

        Ok(Self {
            event_type,
            contract,
            attributes,
        })
    }
}

impl EventFilter {
    pub fn new(
        event_type: Option<nonempty::String>,
        contract: Option<TMAddress>,
        attributes: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            event_type,
            contract,
            attributes,
        }
    }

    pub fn filter(
        &self,
        event_type: &str,
        contract: Option<&TMAddress>,
        attributes: &serde_json::Map<String, serde_json::Value>,
    ) -> bool {
        self.event_type
            .as_ref()
            .is_none_or(|filter| filter.as_str() == event_type)
            && self
                .contract
                .as_ref()
                .is_none_or(|filter| contract == Some(filter))
            && self
                .attributes
                .iter()
                .all(|(key, value)| attributes.get(key) == Some(value))
    }
}

#[derive(Clone, Debug)]
pub struct EventFilters {
    pub filters: Vec<EventFilter>,
    pub include_block_begin_end: bool,
}

impl EventFilters {
    pub fn new(filters: Vec<EventFilter>, include_block_begin_end: bool) -> Self {
        Self {
            filters,
            include_block_begin_end,
        }
    }

    pub fn filter(&self, event: &events::Event) -> bool {
        let contract = event.contract_address();

        match event {
            events::Event::BlockBegin(_) | events::Event::BlockEnd(_) => {
                self.include_block_begin_end
            }
            events::Event::Abci {
                event_type,
                attributes,
            } => self.filter_abci_event(event_type, contract, attributes),
        }
    }

    fn filter_abci_event<T>(
        &self,
        event_type: &str,
        contract: Option<T>,
        attributes: &serde_json::Map<String, serde_json::Value>,
    ) -> bool
    where
        T: Into<TMAddress>,
    {
        if self.filters.is_empty() {
            return true;
        }

        let contract = contract.map(Into::into);

        self.filters
            .iter()
            .any(|filter| filter.filter(event_type, contract.as_ref(), attributes))
    }
}

impl TryFrom<(Vec<ampd_proto::EventFilter>, bool)> for EventFilters {
    type Error = Report<Error>;

    fn try_from(
        (event_filters, include_block_begin_end): (Vec<ampd_proto::EventFilter>, bool),
    ) -> Result<Self, Error> {
        Ok(EventFilters {
            filters: event_filters
                .into_iter()
                .map(EventFilter::try_from)
                .collect::<Result<_, _>>()?,
            include_block_begin_end,
        })
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;

    use super::*;
    use crate::types::TMAddress;
    use crate::PREFIX;

    #[test]
    fn event_filter_should_be_created_from_proto() {
        let event_type = "test_event".to_string();
        let contract = TMAddress::random(PREFIX);
        let mut attributes = HashMap::new();
        attributes.insert(
            "chain_name".to_string(),
            serde_json::Value::String("ethereum".to_string()),
        );
        attributes.insert("object".to_string(), serde_json::json!({ "key": "value" }));

        let proto_filter = ampd_proto::EventFilter {
            r#type: event_type.clone(),
            contract: contract.to_string(),
            attributes: attributes
                .clone()
                .into_iter()
                .map(|(key, value)| (key, value.to_string()))
                .collect(),
        };

        let expected_filter = EventFilter {
            event_type: Some(event_type.parse().unwrap()),
            contract: Some(contract),
            attributes,
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();
        assert_eq!(filter, expected_filter);
    }

    #[test]
    fn event_filter_should_fail_for_empty_filter() {
        let proto_filter = ampd_proto::EventFilter::default();

        let result = EventFilter::try_from(proto_filter);
        assert_err_contains!(result, Error, Error::EmptyFilter);
    }

    #[test]
    fn event_filter_should_fail_for_invalid_contract_address() {
        let proto_filter = ampd_proto::EventFilter {
            r#type: "".to_string(),
            contract: "invalid_address".to_string(),
            attributes: HashMap::new(),
        };

        let result = EventFilter::try_from(proto_filter);
        assert_err_contains!(result, Error, Error::InvalidContractAddress(_));
    }

    #[test]
    fn event_filter_should_fail_for_contract_with_wrong_prefix() {
        let address = TMAddress::random("wrong");
        let proto_filter = ampd_proto::EventFilter {
            r#type: "".to_string(),
            contract: address.to_string(),
            attributes: HashMap::new(),
        };

        let result = EventFilter::try_from(proto_filter);
        assert_err_contains!(result, Error, Error::InvalidContractAddress(_));
    }

    #[test]
    fn event_filter_should_match_by_event_type() {
        let proto_filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "".to_string(),
            attributes: HashMap::new(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();
        assert!(filter.filter("test_event", None, &serde_json::Map::new()));
        assert!(!filter.filter("other_event", None, &serde_json::Map::new()));
    }

    #[test]
    fn event_filter_should_match_by_contract() {
        let address = TMAddress::random(PREFIX);
        let proto_filter = ampd_proto::EventFilter {
            r#type: "".to_string(),
            contract: address.to_string(),
            attributes: HashMap::new(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();

        assert!(filter.filter("any_event", Some(&address), &serde_json::Map::new()));
        assert!(!filter.filter(
            "any_event",
            Some(&TMAddress::random(PREFIX)),
            &serde_json::Map::new()
        ));
        assert!(!filter.filter("any_event", None, &serde_json::Map::new()));
    }

    #[test]
    fn event_filter_should_match_by_attributes() {
        let mut attributes = HashMap::new();
        attributes.insert(
            "chain_name".to_string(),
            serde_json::Value::String("ethereum".to_string()),
        );
        attributes.insert("object".to_string(), serde_json::json!({ "key": "value" }));
        let proto_filter = ampd_proto::EventFilter {
            r#type: "".to_string(),
            contract: "".to_string(),
            attributes: attributes
                .clone()
                .into_iter()
                .map(|(key, value)| (key, value.to_string()))
                .collect(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();

        let mut event_attributes = serde_json::Map::from_iter(attributes);
        assert!(filter.filter("any_event", None, &event_attributes));
        assert!(!filter.filter("any_event", None, &serde_json::Map::new()));

        event_attributes.remove("chain_name");
        assert!(!filter.filter("any_event", None, &event_attributes));
    }

    #[test]
    fn event_filter_should_match_by_all_filters() {
        let address = TMAddress::random(PREFIX);
        let mut attributes = HashMap::new();
        attributes.insert(
            "chain_name".to_string(),
            serde_json::Value::String("ethereum".to_string()),
        );
        attributes.insert("object".to_string(), serde_json::json!({ "key": "value" }));
        let proto_filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: address.to_string(),
            attributes: attributes
                .clone()
                .into_iter()
                .map(|(key, value)| (key, value.to_string()))
                .collect(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();

        let mut event_attributes = serde_json::Map::from_iter(attributes);
        assert!(filter.filter("test_event", Some(&address), &event_attributes));
        assert!(!filter.filter("other_event", Some(&address), &event_attributes));
        assert!(!filter.filter(
            "test_event",
            Some(&TMAddress::random(PREFIX)),
            &event_attributes
        ));

        event_attributes.remove("chain_name");
        assert!(!filter.filter("test_event", Some(&address), &event_attributes));
    }
}
