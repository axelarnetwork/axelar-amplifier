use error_stack::ResultExt;
use router_api::ChainName;

use crate::msg::{ExecuteMsg, QueryMsg};
use crate::{Service, Verifier, WeightedVerifier};

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
            QueryMsg::Service { service_name } => Error::Service(service_name),
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

impl<'a> From<client::Client<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::Client<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::Client<'a, ExecuteMsg, QueryMsg>,
}

impl<'a> Client<'a> {
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

    pub fn service(&self, service_name: String) -> Result<Service> {
        let msg = QueryMsg::Service { service_name };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn verifier(&self, service_name: String, verifier: String) -> Result<Verifier> {
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
    use cosmwasm_std::testing::MockQuerier;
    use cosmwasm_std::{from_json, to_json_binary, Addr, QuerierWrapper, SystemError, WasmQuery};
    use router_api::ChainName;

    use crate::client::Client;
    use crate::msg::QueryMsg;
    use crate::{Service, Verifier, WeightedVerifier};

    #[test]
    fn query_active_verifiers_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let chain_name: ChainName = "ethereum".try_into().unwrap();
        let res = client.active_verifiers(service_name.clone(), chain_name.clone());

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_active_verifiers_returns_active_verifiers() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let chain_name: ChainName = "ethereum".try_into().unwrap();
        let res = client.active_verifiers(service_name.clone(), chain_name.clone());

        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_verifier_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let verifier = Addr::unchecked("verifier").to_string();
        let res = client.verifier(service_name.clone(), verifier.clone());

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_verifier_returns_verifier() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let verifier = Addr::unchecked("verifier").to_string();
        let res = client.verifier(service_name.clone(), verifier.clone());

        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_service_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let res = client.service(service_name.clone());

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_service_returns_service() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), &addr).into();
        let service_name = "verifiers".to_string();
        let res = client.service(service_name.clone());

        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        let addr = "service-registry";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart {
                contract_addr,
                msg: _,
            } if contract_addr == addr => {
                Err(SystemError::Unknown {}).into() // simulate cryptic error seen in production
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, Addr::unchecked(addr))
    }

    fn setup_queries_to_succeed() -> (MockQuerier, Addr) {
        let addr = "service-registry";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::ActiveVerifiers {
                        service_name,
                        chain_name: _,
                    } => Ok(to_json_binary(&vec![WeightedVerifier {
                        verifier_info: Verifier {
                            address: Addr::unchecked("verifier"),
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
                    QueryMsg::Service { service_name } => Ok(to_json_binary(&Service {
                        name: service_name,
                        coordinator_contract: Addr::unchecked("coordinator"),
                        min_num_verifiers: 1,
                        max_num_verifiers: None,
                        min_verifier_bond: Uint128::one(),
                        bond_denom: "uaxl".into(),
                        unbonding_period_days: 10,
                        description: "some service".into(),
                    })
                    .into())
                    .into(),
                    QueryMsg::Verifier {
                        service_name,
                        verifier,
                    } => Ok(to_json_binary(&Verifier {
                        address: Addr::unchecked(verifier),
                        bonding_state: crate::BondingState::Bonded {
                            amount: Uint128::one(),
                        },
                        authorization_state: crate::AuthorizationState::Authorized,
                        service_name,
                    })
                    .into())
                    .into(),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, Addr::unchecked(addr))
    }
}
