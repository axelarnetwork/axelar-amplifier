use error_stack::ResultExt;
use router_api::ChainName;

use crate::msg::{ExecuteMsg, QueryMsg, ServiceParamsOverride, VerifierDetails};
use crate::{Service, WeightedVerifier};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed to query service registry for active verifiers for service {service_name} and chain {chain_name}")]
    ActiveVerifiers {
        service_name: String,
        chain_name: ChainName,
    },

    #[error("failed to query service registry for service {0}")]
    Service(String),

    #[error("failed to query service registry for parameters override for service {service_name} and chain {chain_name}")]
    ServiceParamsOverride {
        service_name: String,
        chain_name: ChainName,
    },

    #[error("failed to query service registry for verifier {verifier} of service {service_name}")]
    Verifier {
        service_name: String,
        verifier: String,
    },
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::ActiveVerifiers {
                service_name,
                chain_name,
            } => Error::ActiveVerifiers {
                service_name,
                chain_name,
            },
            QueryMsg::Service {
                service_name,
                chain_name: _,
            } => Error::Service(service_name),
            QueryMsg::ServiceParamsOverride {
                service_name,
                chain_name,
            } => Error::ServiceParamsOverride {
                service_name,
                chain_name,
            },
            QueryMsg::Verifier {
                service_name,
                verifier,
            } => Error::Verifier {
                service_name,
                verifier,
            },
        }
    }
}

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl Client<'_> {
    // TODO: add execute methods

    pub fn active_verifiers(
        &self,
        service_name: String,
        chain_name: ChainName,
    ) -> Result<Vec<WeightedVerifier>> {
        let msg = QueryMsg::ActiveVerifiers {
            service_name,
            chain_name,
        };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn service(&self, service_name: String, chain_name: Option<ChainName>) -> Result<Service> {
        let msg = QueryMsg::Service {
            service_name,
            chain_name: chain_name.clone(),
        };
        self.client
            .query(&msg)
            .change_context_lazy(|| msg.into())
            .attach_printable_lazy(|| format!("chain_name: {:?}", chain_name))
    }

    pub fn service_params_override(
        &self,
        service_name: String,
        chain_name: ChainName,
    ) -> Result<ServiceParamsOverride> {
        let msg = QueryMsg::ServiceParamsOverride {
            service_name,
            chain_name,
        };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn verifier(&self, service_name: String, verifier: String) -> Result<VerifierDetails> {
        let msg = QueryMsg::Verifier {
            service_name,
            verifier,
        };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}

#[cfg(test)]
mod test {

    use axelar_wasm_std::nonempty::Uint128;
    use cosmwasm_std::testing::{MockApi, MockQuerier};
    use cosmwasm_std::{from_json, to_json_binary, Addr, QuerierWrapper, SystemError, WasmQuery};
    use router_api::ChainName;

    use crate::client::Client;
    use crate::msg::{QueryMsg, ServiceParamsOverride, VerifierDetails};
    use crate::{Service, Verifier, WeightedVerifier};

    #[test]
    fn query_active_verifiers_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let chain_name: ChainName = "ethereum".try_into().unwrap();
        let res = client.active_verifiers(service_name.clone(), chain_name.clone());

        assert!(res.is_err(), "{:?}", res.unwrap());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_active_verifiers_returns_active_verifiers() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let chain_name: ChainName = "ethereum".try_into().unwrap();
        let res = client.active_verifiers(service_name.clone(), chain_name.clone());

        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_verifier_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let verifier = MockApi::default().addr_make("verifier").to_string();
        let res = client.verifier(service_name.clone(), verifier.clone());

        assert!(res.is_err(), "{:?}", res.unwrap());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_verifier_returns_verifier_details() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let verifier = MockApi::default().addr_make("verifier").to_string();
        let res = client.verifier(service_name.clone(), verifier.clone());

        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_service_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let res = client.service(service_name.clone(), None);

        assert!(res.is_err(), "{:?}", res.unwrap());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_service_returns_service() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let res = client.service(service_name.clone(), None);

        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_service_with_chain_name_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let chain_name = "ethereum".try_into().unwrap();
        let res = client.service(service_name, Some(chain_name));

        assert!(res.is_err(), "{:?}", res.unwrap());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_service_with_chain_name_returns_service() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let chain_name = "ethereum".try_into().unwrap();
        let res = client.service(service_name, Some(chain_name));

        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_service_params_override_returns_service_params_override() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let chain_name = "ethereum".try_into().unwrap();
        let res = client.service_params_override(service_name, chain_name);

        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_service_params_override_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let chain_name = "ethereum".try_into().unwrap();
        let res = client.service_params_override(service_name, chain_name);

        assert!(res.is_err(), "{:?}", res.unwrap());
        goldie::assert!(res.unwrap_err().to_string());
    }

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        let api = MockApi::default();
        let addr = api.addr_make("service-registry");
        let addr_clone = addr.clone();

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart {
                contract_addr,
                msg: _,
            } if contract_addr == addr.as_str() => {
                Err(SystemError::Unknown {}).into() // simulate cryptic error seen in production
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, addr_clone)
    }

    fn mock_service(api: &MockApi, service_name: String, chain_name: Option<ChainName>) -> Service {
        Service {
            name: service_name,
            coordinator_contract: api.addr_make("coordinator"),
            min_num_verifiers: chain_name.map_or(1, |_| 2),
            max_num_verifiers: None,
            min_verifier_bond: Uint128::one(),
            bond_denom: "uaxl".into(),
            unbonding_period_days: 10,
            description: "some service".into(),
        }
    }

    fn setup_queries_to_succeed() -> (MockQuerier, Addr) {
        let api = MockApi::default();
        let addr = api.addr_make("service-registry");
        let addr_clone = addr.clone();

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr.as_str() => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::ActiveVerifiers {
                        service_name,
                        chain_name: _,
                    } => Ok(to_json_binary(&vec![WeightedVerifier {
                        verifier_info: Verifier {
                            address: api.addr_make("verifier"),
                            bonding_state: crate::BondingState::Bonded {
                                amount: Uint128::one(),
                            },
                            authorization_state: crate::AuthorizationState::Authorized,
                            service_name,
                        },
                        weight: Uint128::one(),
                    }])
                    .into())
                    .into(),
                    QueryMsg::Service {
                        service_name,
                        chain_name,
                    } => Ok(to_json_binary(&mock_service(&api, service_name, chain_name)).into())
                        .into(),
                    QueryMsg::ServiceParamsOverride {
                        service_name: _,
                        chain_name: _,
                    } => Ok(to_json_binary(&ServiceParamsOverride {
                        min_num_verifiers: Some(2),
                        max_num_verifiers: None,
                    })
                    .into())
                    .into(),
                    QueryMsg::Verifier {
                        service_name,
                        verifier,
                    } => Ok(to_json_binary(&VerifierDetails {
                        verifier: Verifier {
                            address: api.addr_make(&verifier),
                            bonding_state: crate::BondingState::Bonded {
                                amount: Uint128::one(),
                            },
                            authorization_state: crate::AuthorizationState::Authorized,
                            service_name,
                        },
                        weight: Uint128::one(),
                        supported_chains: vec![],
                    })
                    .into())
                    .into(),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, addr_clone)
    }
}
