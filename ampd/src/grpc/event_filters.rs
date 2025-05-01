use std::str::FromStr;

use axelar_wasm_std::nonempty;
use cosmrs::AccountId;
use error_stack::{report, Report, Result};
use report::ResultCompatExt;
use thiserror::Error;
use tonic::Status;

use crate::types::TMAddress;
use crate::{event_sub, PREFIX};

#[derive(Error, Debug)]
pub enum Error {
    #[error("empty filter")]
    EmptyFilter,
    #[error("invalid contract address in filter")]
    InvalidContractAddress(String),
}

impl From<&Error> for Status {
    fn from(error: &Error) -> Self {
        match error {
            Error::EmptyFilter => Status::invalid_argument("empty filter provided"),
            Error::InvalidContractAddress(contract) => Status::invalid_argument(format!(
                "invalid contract address {} provided in filters",
                contract
            )),
        }
    }
}

#[derive(Debug)]
pub struct EventFilter {
    event_type: Option<nonempty::String>,
    contract: Option<TMAddress>,
}

impl TryFrom<ampd_proto::EventFilter> for EventFilter {
    type Error = Report<Error>;

    fn try_from(event_filter: ampd_proto::EventFilter) -> Result<Self, Error> {
        let event_type = event_filter.r#type.try_into().ok();
        let contract = if event_filter.contract.is_empty() {
            None
        } else {
            let contract = AccountId::from_str(&event_filter.contract)
                .change_context(Error::InvalidContractAddress(event_filter.contract.clone()))
                .and_then(|contract| {
                    if contract.prefix() != PREFIX {
                        return Err(report!(Error::InvalidContractAddress(
                            event_filter.contract
                        )));
                    }

                    Ok(contract)
                })
                .map(Into::into)?;

            Some(contract)
        };

        if event_type.is_none() && contract.is_none() {
            return Err(report!(Error::EmptyFilter));
        }

        Ok(EventFilter {
            event_type,
            contract,
        })
    }
}

impl EventFilter {
    pub fn filter(&self, event_type: &str, contract: &Option<TMAddress>) -> bool {
        if self
            .event_type
            .as_ref()
            .is_some_and(|filter| *filter != event_type)
        {
            return false;
        }

        if self.contract.is_some() && self.contract != *contract {
            return false;
        }

        true
    }
}

#[derive(Debug)]
pub struct EventFilters {
    filters: Vec<EventFilter>,
    include_block_begin_end: bool,
}

impl EventFilters {
    pub fn filter(&self, event: &Result<events::Event, event_sub::Error>) -> bool {
        match event {
            Ok(event) => {
                let contract = event.contract_address();

                match event {
                    events::Event::BlockBegin(_) | events::Event::BlockEnd(_) => {
                        self.include_block_begin_end
                    }
                    events::Event::Abci { event_type, .. } => {
                        self.filter_abci_event(event_type, contract)
                    }
                }
            }
            Err(_) => true,
        }
    }

    fn filter_abci_event<T>(&self, event_type: &str, contract: Option<T>) -> bool
    where
        T: Into<TMAddress>,
    {
        if self.filters.is_empty() {
            return true;
        }

        let contract = contract.map(Into::into);

        self.filters
            .iter()
            .any(|filter| filter.filter(event_type, &contract))
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
    use std::iter;

    use axelar_wasm_std::assert_err_contains;
    use error_stack::report;
    use events::Event;
    use serde_json::{Map, Value};

    use super::*;
    use crate::types::TMAddress;

    #[test]
    fn event_filter_should_be_created_from_valid_event_filter() {
        let proto_filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "".to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();
        assert!(filter.event_type.is_some());
        assert!(filter.contract.is_none());
    }

    #[test]
    fn event_filter_should_be_created_from_valid_contract_address() {
        let address = TMAddress::random(PREFIX);
        let proto_filter = ampd_proto::EventFilter {
            r#type: "".to_string(),
            contract: address.to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();
        assert!(filter.event_type.is_none());
        assert_eq!(filter.contract.as_ref(), Some(&address));
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
        };

        let result = EventFilter::try_from(proto_filter);
        assert_err_contains!(result, Error, Error::InvalidContractAddress(_));
    }

    #[test]
    fn event_filter_should_match_by_event_type() {
        let proto_filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "".to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();
        assert!(filter.filter("test_event", &None));
        assert!(!filter.filter("other_event", &None));
    }

    #[test]
    fn event_filter_should_match_by_contract() {
        let address = TMAddress::random(PREFIX);
        let proto_filter = ampd_proto::EventFilter {
            r#type: "".to_string(),
            contract: address.to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();

        assert!(filter.filter("any_event", &Some(address.clone())));
        assert!(!filter.filter("any_event", &Some(TMAddress::random(PREFIX))));
        assert!(!filter.filter("any_event", &None));
    }

    #[test]
    fn event_filter_should_match_by_both_event_type_and_contract() {
        let address = TMAddress::random(PREFIX);
        let proto_filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: address.to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();

        assert!(filter.filter("test_event", &Some(address.clone())));
        assert!(!filter.filter("other_event", &Some(address.clone())));
        assert!(!filter.filter("test_event", &Some(TMAddress::random(PREFIX))));
    }

    #[test]
    fn event_filters_should_be_created_from_valid_proto_filters() {
        let proto_filters = vec![ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "".to_string(),
        }];

        let filters = EventFilters::try_from((proto_filters, true)).unwrap();
        assert_eq!(filters.filters.len(), 1);
        assert!(filters.include_block_begin_end);
    }

    #[test]
    fn event_filters_should_fail_if_any_filter_is_invalid() {
        let proto_filters = vec![
            ampd_proto::EventFilter {
                r#type: "test_event".to_string(),
                contract: "".to_string(),
            },
            ampd_proto::EventFilter::default(),
        ];

        let result = EventFilters::try_from((proto_filters, true));
        assert_err_contains!(result, Error, Error::EmptyFilter);
    }

    #[test]
    fn event_filters_should_include_block_events_when_configured() {
        let proto_filters = vec![ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "".to_string(),
        }];

        let filters = EventFilters::try_from((proto_filters, true)).unwrap();
        assert!(filters.filter(&Ok(Event::BlockBegin(100u32.into()))));
        assert!(filters.filter(&Ok(Event::BlockEnd(100u32.into()))));
    }

    #[test]
    fn event_filters_should_exclude_block_events_when_configured() {
        let proto_filters = vec![ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "".to_string(),
        }];

        let filters = EventFilters::try_from((proto_filters, false)).unwrap();
        assert!(!filters.filter(&Ok(Event::BlockBegin(100u32.into()))));
        assert!(!filters.filter(&Ok(Event::BlockEnd(100u32.into()))));
    }

    #[test]
    fn event_filters_should_match_abci_events_with_matching_filters() {
        let proto_filters = vec![ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "".to_string(),
        }];

        let filters = EventFilters::try_from((proto_filters, false)).unwrap();
        assert!(filters.filter(&Ok(Event::Abci {
            event_type: "test_event".to_string(),
            attributes: Map::new(),
        })));
        assert!(!filters.filter(&Ok(Event::Abci {
            event_type: "other_event".to_string(),
            attributes: Map::new(),
        })));
    }

    #[test]
    fn event_filters_should_match_any_filter_in_multiple_filters() {
        let address = TMAddress::random(PREFIX);
        let proto_filters = vec![
            ampd_proto::EventFilter {
                r#type: "event_1".to_string(),
                contract: "".to_string(),
            },
            ampd_proto::EventFilter {
                r#type: "".to_string(),
                contract: address.to_string(),
            },
        ];

        let filters = EventFilters::try_from((proto_filters, false)).unwrap();
        assert!(filters.filter(&Ok(Event::Abci {
            event_type: "event_1".to_string(),
            attributes: Map::new(),
        })));
        assert!(filters.filter(&Ok(Event::Abci {
            event_type: "any_event".to_string(),
            attributes: iter::once((
                "_contract_address".to_string(),
                Value::String(address.to_string()),
            ))
            .collect(),
        })));
        assert!(!filters.filter(&Ok(Event::Abci {
            event_type: "event_2".to_string(),
            attributes: Map::new(),
        })));
    }

    #[test]
    fn event_filters_should_allow_all_events_when_no_filters_provided() {
        let filters = EventFilters::try_from((vec![], true)).unwrap();

        assert!(filters.filter(&Ok(Event::Abci {
            event_type: "any_event".to_string(),
            attributes: Map::new(),
        })));
    }

    #[test]
    fn event_filters_should_always_allow_error_events() {
        let proto_filters = vec![ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "".to_string(),
        }];

        let filters = EventFilters::try_from((proto_filters, false)).unwrap();
        assert!(filters.filter(&Err(report!(event_sub::Error::LatestBlockQuery))));
    }
}
