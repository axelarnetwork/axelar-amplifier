use error_stack::ResultExt;
use router_api::ChainName;

use crate::msg::{ExecuteMsg, QueryMsg};
use crate::{Service, Verifier, WeightedVerifier};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed query the service registry for active verifiers for service {service_name} and chain {chain_name}")]
    QueryActiveVerifiers {
        service_name: String,
        chain_name: ChainName,
    },

    #[error("failed to query service registry for service {0}")]
    QueryService(String),

    #[error("failed to query service registry for verifier {verifier} of service {service_name}")]
    QueryVerifier {
        service_name: String,
        verifier: String,
    },
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
        self.client
            .query(&QueryMsg::ActiveVerifiers {
                service_name: service_name.clone(),
                chain_name: chain_name.clone(),
            })
            .change_context_lazy(|| Error::QueryActiveVerifiers {
                service_name,
                chain_name,
            })
    }

    pub fn service(&self, service_name: String) -> Result<Service> {
        self.client
            .query(&QueryMsg::Service {
                service_name: service_name.clone(),
            })
            .change_context_lazy(|| Error::QueryService(service_name))
    }

    pub fn verifier(&self, service_name: String, verifier: String) -> Result<Verifier> {
        self.client
            .query(&QueryMsg::Verifier {
                service_name: service_name.clone(),
                verifier: verifier.clone(),
            })
            .change_context_lazy(|| Error::QueryVerifier {
                service_name,
                verifier,
            })
    }
}

#[cfg(test)]
mod test {

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MockQuerier};
    use cosmwasm_std::{from_json, Addr, DepsMut, QuerierWrapper, WasmQuery};
    use router_api::ChainName;

    use crate::client::{Client, Error};
    use crate::contract::{instantiate, query};
    use crate::msg::{InstantiateMsg, QueryMsg};

    #[test]
    fn query_active_verifiers_error() {
        let (querier, _, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();
        let service_name = "verifiers".to_string();
        let chain_name: ChainName = "ethereum".try_into().unwrap();
        let res = client.active_verifiers(service_name.clone(), chain_name.clone());
        assert!(res.is_err());

        assert_eq!(
            res.unwrap_err().to_string(),
            Error::QueryActiveVerifiers {
                service_name,
                chain_name
            }
            .to_string(),
        );
    }

    #[test]
    fn query_verifier_error() {
        let (querier, _, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();
        let service_name = "verifiers".to_string();
        let verifier = Addr::unchecked("verifier").to_string();
        let res = client.verifier(service_name.clone(), verifier.clone());
        assert!(res.is_err());

        assert_eq!(
            res.unwrap_err().to_string(),
            Error::QueryVerifier {
                service_name,
                verifier: verifier.to_string()
            }
            .to_string()
        );
    }

    #[test]
    fn query_service_error() {
        let (querier, _, addr) = setup();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), addr).into();
        let service_name = "verifiers".to_string();
        let res = client.service(service_name.clone());
        assert!(res.is_err());

        assert_eq!(
            res.unwrap_err().to_string(),
            Error::QueryService(service_name).to_string()
        );
    }

    fn setup() -> (MockQuerier, InstantiateMsg, Addr) {
        let addr = "service-registry";
        let mut deps = mock_dependencies();
        let instantiate_msg = instantiate_contract(deps.as_mut());

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, instantiate_msg, Addr::unchecked(addr))
    }

    fn instantiate_contract(deps: DepsMut) -> InstantiateMsg {
        let env = mock_env();
        let info = mock_info("deployer", &[]);

        let msg = InstantiateMsg {
            governance_account: "governance".into(),
        };

        instantiate(deps, env, info.clone(), msg.clone()).unwrap();

        msg
    }
}
