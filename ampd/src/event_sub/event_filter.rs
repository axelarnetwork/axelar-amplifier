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

#[derive(Clone, Debug)]
pub enum EventFilter {
    EventType(nonempty::String),
    Contract(TMAddress),
    EventTypeAndContract(nonempty::String, TMAddress),
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

        match (event_type, contract) {
            (Some(event_type), Some(contract)) => {
                Ok(EventFilter::EventTypeAndContract(event_type, contract))
            }
            (Some(event_type), None) => Ok(EventFilter::EventType(event_type)),
            (None, Some(contract)) => Ok(EventFilter::Contract(contract)),
            (None, None) => Err(report!(Error::EmptyFilter)),
        }
    }
}

impl EventFilter {
    pub fn filter(&self, event_type: &str, contract: Option<&TMAddress>) -> bool {
        match self {
            EventFilter::EventType(event_type_filter) => event_type_filter == event_type,
            EventFilter::Contract(contract_filter) => Some(contract_filter) == contract,
            EventFilter::EventTypeAndContract(event_type_filter, contract_filter) => {
                event_type_filter == event_type && Some(contract_filter) == contract
            }
        }
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
            events::Event::Abci { event_type, .. } => self.filter_abci_event(event_type, contract),
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
            .any(|filter| filter.filter(event_type, contract.as_ref()))
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
    fn event_filter_should_be_created_from_valid_event_type() {
        let proto_filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "".to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();
        assert!(matches!(filter, EventFilter::EventType(_)));
    }

    #[test]
    fn event_filter_should_be_created_from_valid_contract_address() {
        let proto_filter = ampd_proto::EventFilter {
            r#type: "".to_string(),
            contract: TMAddress::random(PREFIX).to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();
        assert!(matches!(filter, EventFilter::Contract(_)));
    }

    #[test]
    fn event_filter_should_be_created_from_valid_event_type_and_contract_address() {
        let proto_filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: TMAddress::random(PREFIX).to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();
        assert!(matches!(filter, EventFilter::EventTypeAndContract(_, _)));
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
        assert!(filter.filter("test_event", None));
        assert!(!filter.filter("other_event", None));
    }

    #[test]
    fn event_filter_should_match_by_contract() {
        let address = TMAddress::random(PREFIX);
        let proto_filter = ampd_proto::EventFilter {
            r#type: "".to_string(),
            contract: address.to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();

        assert!(filter.filter("any_event", Some(&address)));
        assert!(!filter.filter("any_event", Some(&TMAddress::random(PREFIX))));
        assert!(!filter.filter("any_event", None));
    }

    #[test]
    fn event_filter_should_match_by_both_event_type_and_contract() {
        let address = TMAddress::random(PREFIX);
        let proto_filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: address.to_string(),
        };

        let filter = EventFilter::try_from(proto_filter).unwrap();

        assert!(filter.filter("test_event", Some(&address)));
        assert!(!filter.filter("other_event", Some(&address)));
        assert!(!filter.filter("test_event", Some(&TMAddress::random(PREFIX))));
    }
}
