use std::collections::HashMap;

use axelar_wasm_std::nonempty;
use error_stack::{report, Report, Result, ResultExt};
use serde::Serialize;
use thiserror::Error;
use typed_builder::TypedBuilder;

use crate::types::{AxelarAddress, TMAddress};

#[derive(Error, Debug)]
pub enum Error {
    #[error("empty filter")]
    EmptyFilter,
    #[error("invalid contract address {0}")]
    InvalidContractAddress(String),
}

/// Marker trait for typed_builder typestate tuples where at least one field is set.
/// Used to ensure `EventFilter::build()` can only be called when at least one
/// filter criterion has been specified.
pub trait AtLeastOne {}

/// Generates `AtLeastOne` implementations for all typestate tuple combinations
/// where at least one field is set.
///
/// typed_builder represents each field's state as either `()` (unset) or `(T,)` (set).
/// This macro generates impls for all 2^n - 1 valid combinations (excluding all-unset).
///
/// # Example
///
/// ```ignore
/// at_least_one!(A, B);
/// ```
///
/// Expands to:
///
/// ```ignore
/// impl AtLeastOne for ((A,), (B,)) {}  // both set
/// impl AtLeastOne for ((A,), ())   {}  // first set
/// impl AtLeastOne for ((), (B,))   {}  // second set
/// // ((), ()) is excluded - nothing set
/// ```
#[macro_export]
macro_rules! at_least_one {
    ($($field_ty:ty),+) => {
        at_least_one!(@impls AtLeastOne; (); $($field_ty),+);
    };

    // Recursive case: for each field, branch into set `($head,)` and unset `()`
    // Example: at_least_one!(@impls T; (); A, B)
    //   -> at_least_one!(@impls T; ((A,),); B)  // A set
    //   -> at_least_one!(@impls T; ((),); B)    // A unset
    (@impls $trait:ident; ($($acc:tt)*); $head:ty $(, $tail:ty)*) => {
        at_least_one!(@impls $trait; ($($acc)* ($head,),); $($tail),*);
        at_least_one!(@impls $trait; ($($acc)* (),); $($tail),*);
    };

    // Base case: all fields unset - do not emit impl
    // Example: ((), ()) matches ($((),)*) - no impl generated
    (@impls $trait:ident; ($((),)*); ) => {};

    // Base case: at least one field set - emit impl
    // Example: ((A,), ()) -> impl AtLeastOne for ((A,), ()) {}
    (@impls $trait:ident; ($($tuple:tt)*); ) => {
        impl $trait for ($($tuple)*) {}
    };
}

at_least_one!(
    Option<nonempty::String>,
    Option<TMAddress>,
    Option<nonempty::HashMap<String, serde_json::Value>>
);

#[derive(Clone, Debug, PartialEq, Eq, TypedBuilder, Serialize)]
#[builder(build_method(vis = "", name = build_internal))]
pub struct EventFilter {
    #[builder(default, setter(strip_option))]
    event_type: Option<nonempty::String>,
    #[builder(default, setter(strip_option))]
    contract: Option<TMAddress>,
    #[builder(default, setter(strip_option))]
    attributes: Option<nonempty::HashMap<String, serde_json::Value>>,
}

impl<E, C, A> EventFilterBuilder<(E, C, A)>
where
    E: ::typed_builder::Optional<Option<nonempty::String>>,
    C: ::typed_builder::Optional<Option<TMAddress>>,
    A: ::typed_builder::Optional<Option<nonempty::HashMap<String, serde_json::Value>>>,
    (E, C, A): AtLeastOne,
{
    pub fn build(self) -> EventFilter {
        self.build_internal()
    }
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
        let attributes = event_filter
            .attributes
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    serde_json::from_str(&value).unwrap_or(serde_json::Value::String(value)),
                )
            })
            .collect::<HashMap<_, _>>()
            .try_into()
            .ok();

        if event_type.is_none() && contract.is_none() && attributes.is_none() {
            return Err(report!(Error::EmptyFilter));
        }

        // outside of this try_from function the builder should be used to make sure the type is valid at compile-time
        Ok(Self {
            event_type,
            contract,
            attributes,
        })
    }
}

impl EventFilter {
    pub fn filter(
        &self,
        event_type: &str,
        contract: Option<&TMAddress>,
        attributes: &serde_json::Map<String, serde_json::Value>,
    ) -> bool {
        self.event_type
            .as_ref()
            .is_none_or(|filter| filter == event_type)
            && self
                .contract
                .as_ref()
                .is_none_or(|filter| contract == Some(filter))
            && self.attributes.as_ref().is_none_or(|attrs| {
                attrs
                    .iter()
                    .all(|(key, value)| attributes.get(key) == Some(value))
            })
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
        let proto_filter = ampd_proto::EventFilter {
            r#type: "test_event".to_string(),
            contract: "axelar1m7rj8s9ee46h3sx96z9jg4hznhx5jzfp7dwv2u".to_string(),
            attributes: [
                ("chain_name".to_string(), r#""ethereum""#.to_string()),
                ("object".to_string(), r#"{"key":"value"}"#.to_string()),
            ]
            .into(),
        };

        let filter = EventFilter::try_from(proto_filter);
        assert!(filter.is_ok(), "{:?}", filter.unwrap_err());

        // This seems stable despite non-determistic ordering of HashMap entries.
        // Should tests start to fail, this needs to be changed to a different type of test.
        goldie::assert_json!(filter.unwrap());
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
