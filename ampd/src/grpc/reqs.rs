use std::str::FromStr;

use ampd_proto::{
    Algorithm, BroadcastRequest, ContractStateRequest, ContractsRequest, KeyId, KeyRequest,
    SignRequest, SubscribeRequest,
};
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::nonempty;
use cosmrs::Any;
use error_stack::{bail, ensure, report, Report, Result, ResultExt};
use report::ResultCompatExt;
use thiserror::Error;
use tonic::Request;

use crate::types::TMAddress;
use crate::{tofnd, PREFIX};

type ContractQuery = Vec<u8>;
type KeyIdString = nonempty::String;
type SignMessage = [u8; 32];

pub trait Validate {
    type Output;

    fn validate(self) -> Result<Self::Output, Error>;
}

impl Validate for Request<SubscribeRequest> {
    type Output = EventFilters;

    fn validate(self) -> Result<Self::Output, Error> {
        let SubscribeRequest {
            filters,
            include_block_begin_end,
        } = self.into_inner();

        (filters, include_block_begin_end).try_into()
    }
}

impl Validate for Request<BroadcastRequest> {
    type Output = Any;

    fn validate(self) -> Result<Self::Output, Error> {
        self.into_inner()
            .msg
            .ok_or(report!(Error::EmptyBroadcastMsg))
    }
}

impl Validate for Request<ContractStateRequest> {
    type Output = (TMAddress, ContractQuery);

    fn validate(self) -> Result<Self::Output, Error> {
        let ContractStateRequest { contract, query } = self.into_inner();

        ensure!(!query.is_empty(), Error::InvalidQuery);
        let _: serde_json::Value =
            serde_json::from_slice(&query).change_context(Error::InvalidQuery)?;

        Ok((validate_address(&contract)?, query))
    }
}

fn validate_address(address: &str) -> Result<TMAddress, Error> {
    let address = TMAddress::from_str(address)
        .change_context(Error::InvalidContractAddress(address.to_string()))?;
    ensure!(
        address.prefix() == PREFIX,
        Error::InvalidContractAddress(address.to_string())
    );

    Ok(address)
}

impl Validate for Request<ContractsRequest> {
    type Output = ChainName;

    fn validate(self) -> Result<Self::Output, Error> {
        let ContractsRequest { chain } = self.into_inner();

        ChainName::try_from(chain.as_str()).change_context(Error::InvalidChainName(chain))
    }
}

impl Validate for Request<KeyRequest> {
    type Output = (KeyIdString, tofnd::Algorithm);

    fn validate(self) -> Result<Self::Output, Error> {
        let KeyRequest { key_id } = self.into_inner();

        validate_key_id(key_id.unwrap_or_default())
    }
}

impl Validate for Request<SignRequest> {
    type Output = (KeyIdString, tofnd::Algorithm, SignMessage);

    fn validate(self) -> Result<Self::Output, Error> {
        let SignRequest { key_id, msg } = self.into_inner();

        let (id, algorithm) = validate_key_id(key_id.unwrap_or_default())?;
        let msg = msg
            .try_into()
            .map_err(|msg| report!(Error::InvalidSignMsg(msg)))?;

        Ok((id, algorithm, msg))
    }
}

fn validate_key_id(key_id: KeyId) -> Result<(KeyIdString, tofnd::Algorithm), Error> {
    let KeyId { id, algorithm } = key_id;

    let id = nonempty::String::try_from(id).change_context(Error::EmptyKeyId)?;
    let algorithm = match algorithm.try_into() {
        Ok(Algorithm::Ecdsa) => tofnd::Algorithm::Ecdsa,
        Ok(Algorithm::Ed25519) => tofnd::Algorithm::Ed25519,
        Ok(Algorithm::Unspecified) | Err(_) => {
            bail!(Error::InvalidCryptoAlgorithm(algorithm));
        }
    };

    Ok((id, algorithm))
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("empty filter")]
    EmptyFilter,
    #[error("invalid contract address {0}")]
    InvalidContractAddress(String),
    #[error("invalid query")]
    InvalidQuery,
    #[error("empty broadcast message")]
    EmptyBroadcastMsg,
    #[error("empty key id")]
    EmptyKeyId,
    #[error("invalid crypto algorithm {0}")]
    InvalidCryptoAlgorithm(i32),
    #[error("invalid 32-byte sign message {0:?}")]
    InvalidSignMsg(Vec<u8>),
    #[error("invalid chain name {0}")]
    InvalidChainName(String),
}

#[derive(Debug)]
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
            Some(validate_address(&event_filter.contract)?)
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

#[derive(Debug)]
pub struct EventFilters {
    filters: Vec<EventFilter>,
    include_block_begin_end: bool,
}

impl EventFilters {
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
    use std::iter;

    use axelar_wasm_std::assert_err_contains;
    use events::Event;
    use serde_json::{Map, Value};

    use super::*;
    use crate::types::TMAddress;

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

    #[test]
    fn event_filters_should_be_created_from_valid_proto_filters() {
        let req = Request::new(SubscribeRequest {
            filters: vec![ampd_proto::EventFilter {
                r#type: "test_event".to_string(),
                contract: "".to_string(),
            }],
            include_block_begin_end: true,
        });

        let filters = req.validate().unwrap();
        assert_eq!(filters.filters.len(), 1);
        assert!(filters.include_block_begin_end);
    }

    #[test]
    fn event_filters_should_fail_if_any_filter_is_invalid() {
        let req = Request::new(SubscribeRequest {
            filters: vec![
                ampd_proto::EventFilter {
                    r#type: "test_event".to_string(),
                    contract: "".to_string(),
                },
                ampd_proto::EventFilter::default(),
            ],
            include_block_begin_end: true,
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::EmptyFilter);
    }

    #[test]
    fn event_filters_should_include_block_events_when_configured() {
        let req = Request::new(SubscribeRequest {
            filters: vec![ampd_proto::EventFilter {
                r#type: "test_event".to_string(),
                contract: "".to_string(),
            }],
            include_block_begin_end: true,
        });

        let filters = req.validate().unwrap();
        assert!(filters.filter(&Event::BlockBegin(100u32.into())));
        assert!(filters.filter(&Event::BlockEnd(100u32.into())));
    }

    #[test]
    fn event_filters_should_exclude_block_events_when_configured() {
        let req = Request::new(SubscribeRequest {
            filters: vec![ampd_proto::EventFilter {
                r#type: "test_event".to_string(),
                contract: "".to_string(),
            }],
            include_block_begin_end: false,
        });

        let filters = req.validate().unwrap();
        assert!(!filters.filter(&Event::BlockBegin(100u32.into())));
        assert!(!filters.filter(&Event::BlockEnd(100u32.into())));
    }

    #[test]
    fn event_filters_should_match_abci_events_with_matching_filters() {
        let req = Request::new(SubscribeRequest {
            filters: vec![ampd_proto::EventFilter {
                r#type: "test_event".to_string(),
                contract: "".to_string(),
            }],
            include_block_begin_end: false,
        });

        let filters = req.validate().unwrap();
        assert!(filters.filter(&Event::Abci {
            event_type: "test_event".to_string(),
            attributes: Map::new(),
        }));
        assert!(!filters.filter(&Event::Abci {
            event_type: "other_event".to_string(),
            attributes: Map::new(),
        }));
    }

    #[test]
    fn event_filters_should_match_any_filter_in_multiple_filters() {
        let address = TMAddress::random(PREFIX);
        let req = Request::new(SubscribeRequest {
            filters: vec![
                ampd_proto::EventFilter {
                    r#type: "event_1".to_string(),
                    contract: "".to_string(),
                },
                ampd_proto::EventFilter {
                    r#type: "".to_string(),
                    contract: address.to_string(),
                },
            ],
            include_block_begin_end: false,
        });

        let filters = req.validate().unwrap();
        assert!(filters.filter(&Event::Abci {
            event_type: "event_1".to_string(),
            attributes: Map::new(),
        }));
        assert!(filters.filter(&Event::Abci {
            event_type: "any_event".to_string(),
            attributes: iter::once((
                "_contract_address".to_string(),
                Value::String(address.to_string()),
            ))
            .collect(),
        }));
        assert!(!filters.filter(&Event::Abci {
            event_type: "event_2".to_string(),
            attributes: Map::new(),
        }));
    }

    #[test]
    fn event_filters_should_allow_all_events_when_no_filters_provided() {
        let req = Request::new(SubscribeRequest {
            filters: vec![],
            include_block_begin_end: true,
        });

        let filters = req.validate().unwrap();
        assert!(filters.filter(&Event::Abci {
            event_type: "any_event".to_string(),
            attributes: Map::new(),
        }));
    }

    #[test]
    fn validate_broadcast_should_work() {
        let req = Request::new(BroadcastRequest {
            msg: Some(Any {
                type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
                value: vec![1, 2, 3],
            }),
        });
        let msg = req.validate().unwrap();
        assert_eq!(msg.type_url, "/cosmos.bank.v1beta1.MsgSend");
        assert_eq!(msg.value, vec![1, 2, 3]);

        let req = Request::new(BroadcastRequest { msg: None });
        assert_err_contains!(req.validate(), Error, Error::EmptyBroadcastMsg);
    }

    #[test]
    fn validate_contract_state_should_extract_contract_and_query() {
        let address = TMAddress::random(PREFIX);
        let query_json = serde_json::json!({"get_config": {}});
        let query_bytes = serde_json::to_vec(&query_json).unwrap();

        let req = Request::new(ContractStateRequest {
            contract: address.to_string(),
            query: query_bytes.clone(),
        });

        let (result_address, result_query) = req.validate().unwrap();
        assert_eq!(result_address, address);
        assert_eq!(result_query, query_bytes);
    }

    #[test]
    fn validate_contract_state_should_fail_on_empty_query() {
        let address = TMAddress::random(PREFIX);
        let req = Request::new(ContractStateRequest {
            contract: address.to_string(),
            query: vec![],
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::InvalidQuery);
    }

    #[test]
    fn validate_contract_state_should_fail_on_invalid_json() {
        let address = TMAddress::random(PREFIX);
        let req = Request::new(ContractStateRequest {
            contract: address.to_string(),
            query: vec![1, 2, 3], // invalid JSON bytes
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::InvalidQuery);
    }

    #[test]
    fn validate_contract_state_should_fail_on_invalid_contract_address() {
        let query_json = serde_json::json!({"get_config": {}});
        let query_bytes = serde_json::to_vec(&query_json).unwrap();

        let req = Request::new(ContractStateRequest {
            contract: "invalid_address".to_string(),
            query: query_bytes,
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::InvalidContractAddress(_));
    }

    #[test]
    fn validate_contract_state_should_fail_on_contract_with_wrong_prefix() {
        let address = TMAddress::random("wrong");
        let query_json = serde_json::json!({"get_config": {}});
        let query_bytes = serde_json::to_vec(&query_json).unwrap();

        let req = Request::new(ContractStateRequest {
            contract: address.to_string(),
            query: query_bytes,
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::InvalidContractAddress(_));
    }

    #[test]
    fn validate_key_should_extract_key_id_and_algorithm() {
        let key_id = "test_key";
        let algorithm = ampd_proto::Algorithm::Ecdsa;

        let req = Request::new(KeyRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
        });

        let (result_id, result_algorithm) = req.validate().unwrap();
        assert_eq!(result_id.as_str(), key_id);
        assert_eq!(result_algorithm, tofnd::Algorithm::Ecdsa);
    }

    #[test]
    fn validate_key_should_use_default_key_id_when_none_provided() {
        let req = Request::new(KeyRequest { key_id: None });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::EmptyKeyId);
    }

    #[test]
    fn validate_key_should_handle_ed25519_algorithm() {
        let key_id = "test_key";
        let algorithm = ampd_proto::Algorithm::Ed25519;

        let req = Request::new(KeyRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
        });

        let (result_id, result_algorithm) = req.validate().unwrap();
        assert_eq!(result_id.as_str(), key_id);
        assert_eq!(result_algorithm, tofnd::Algorithm::Ed25519);
    }

    #[test]
    fn validate_key_should_fail_with_empty_key_id() {
        let req = Request::new(KeyRequest {
            key_id: Some(KeyId {
                id: "".to_string(),
                algorithm: ampd_proto::Algorithm::Ecdsa.into(),
            }),
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::EmptyKeyId);
    }

    #[test]
    fn validate_key_should_fail_with_invalid_algorithm() {
        let key_id = "test_key";
        let invalid_algorithm = 999; // some invalid algorithm value

        let req = Request::new(KeyRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: invalid_algorithm,
            }),
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::InvalidCryptoAlgorithm(_));
    }

    #[test]
    fn validate_sign_should_extract_key_id_algorithm_and_message() {
        let key_id = "test_key";
        let algorithm = ampd_proto::Algorithm::Ecdsa;
        let message = vec![0; 32];

        let req = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
            msg: message.clone(),
        });

        let (result_id, result_algorithm, result_msg) = req.validate().unwrap();
        assert_eq!(result_id.as_str(), key_id);
        assert_eq!(result_algorithm, tofnd::Algorithm::Ecdsa);
        assert_eq!(result_msg.to_vec(), message);
    }

    #[test]
    fn validate_sign_should_fail_when_no_key_id_is_provided() {
        let message = vec![1, 2, 3, 4];
        let req = Request::new(SignRequest {
            key_id: None,
            msg: message,
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::EmptyKeyId);
    }

    #[test]
    fn validate_sign_should_handle_ed25519_algorithm() {
        let key_id = "test_key";
        let algorithm = ampd_proto::Algorithm::Ed25519;
        let message = vec![0; 32];

        let req = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
            msg: message.clone(),
        });

        let (result_id, result_algorithm, result_msg) = req.validate().unwrap();
        assert_eq!(result_id.as_str(), key_id);
        assert_eq!(result_algorithm, tofnd::Algorithm::Ed25519);
        assert_eq!(result_msg.to_vec(), message);
    }

    #[test]
    fn validate_sign_should_fail_with_empty_key_id() {
        let message = vec![0; 32];

        let req = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: "".to_string(),
                algorithm: ampd_proto::Algorithm::Ecdsa.into(),
            }),
            msg: message,
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::EmptyKeyId);
    }

    #[test]
    fn validate_sign_should_fail_with_invalid_algorithm() {
        let key_id = "test_key";
        let invalid_algorithm = 999; // some invalid algorithm value
        let message = vec![0; 32];

        let req = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: invalid_algorithm,
            }),
            msg: message,
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::InvalidCryptoAlgorithm(_));
    }

    #[test]
    fn validate_sign_should_fail_with_empty_message() {
        let key_id = "test_key";
        let algorithm = ampd_proto::Algorithm::Ecdsa;

        let req = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
            msg: vec![],
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::InvalidSignMsg(_));
    }

    #[test]
    fn validate_sign_should_fail_with_longer_than_32_byte_message() {
        let key_id = "test_key";
        let algorithm = ampd_proto::Algorithm::Ecdsa;

        let req = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
            msg: vec![0; 33],
        });

        let result = req.validate();
        assert_err_contains!(result, Error, Error::InvalidSignMsg(_));
    }
}
