use std::collections::HashSet;

use axelar_wasm_std::nonempty;
use cosmwasm_std::{Addr, CosmosMsg};
use error_stack::{Result, ResultExt};
use router_api::ChainName;

use crate::msg::{ChainContractsKey, ChainContractsResponse, ExecuteMsg, QueryMsg};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("coordinator failed to retrieve if verifier {0} is ready to unbond.")]
    ReadyToUnbond(String),

    #[error("failed to query ChainContractsInfo by chain name {0}")]
    ChainNameNotRegistered(String),

    #[error("failed to query ChainContractsInfo by gateway {0}")]
    GatewayNotRegistered(Addr),

    #[error("failed to query ChainContractsInfo by prover {0}")]
    ProverNotRegistered(Addr),

    #[error("failed to query ChainContractsInfo by verifier {0}")]
    VerifierNotRegistered(Addr),

    #[error("deployment {0} not found")]
    DeploymentNotFound(nonempty::String),

    #[error("failed to retrieve deployments")]
    Deployments,
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
    pub fn register_protocol(
        &self,
        router: &Addr,
        service_registry: &Addr,
        multisig: &Addr,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::RegisterProtocol {
            service_registry_address: service_registry.to_string(),
            router_address: router.to_string(),
            multisig_address: multisig.to_string(),
        })
    }

    pub fn register_chain(
        &self,
        chain_name: ChainName,
        prover_address: String,
        gateway_address: String,
        voting_verifier_address: String,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::RegisterChain {
            chain_name,
            prover_address,
            gateway_address,
            voting_verifier_address,
        })
    }

    pub fn set_active_verifiers(&self, verifiers: HashSet<String>) -> CosmosMsg {
        self.client
            .execute(&ExecuteMsg::SetActiveVerifiers { verifiers })
    }

    pub fn ready_to_unbond(&self, verifier_address: String) -> Result<bool, Error> {
        let msg = QueryMsg::ReadyToUnbond {
            verifier_address: verifier_address.clone(),
        };

        self.client
            .query(&msg)
            .change_context(Error::ReadyToUnbond(verifier_address))
    }

    pub fn chain_contracts(
        &self,
        chain_contracts_key: ChainContractsKey,
    ) -> Result<ChainContractsResponse, Error> {
        let msg = QueryMsg::ChainContractsInfo(chain_contracts_key.clone());
        self.client
            .query(&msg)
            .change_context(match chain_contracts_key {
                ChainContractsKey::GatewayAddress(gateway_addr) => {
                    Error::GatewayNotRegistered(gateway_addr)
                }
                ChainContractsKey::ProverAddress(prover_addr) => {
                    Error::ProverNotRegistered(prover_addr)
                }
                ChainContractsKey::VerifierAddress(verifier_addr) => {
                    Error::VerifierNotRegistered(verifier_addr)
                }
                ChainContractsKey::ChainName(chain_name) => {
                    Error::ChainNameNotRegistered(chain_name.into())
                }
            })
    }

    pub fn deployment(
        &self,
        deployment_name: nonempty::String,
    ) -> Result<ChainContractsResponse, Error> {
        let msg = QueryMsg::Deployment {
            deployment_name: deployment_name.clone(),
        };
        self.client
            .query(&msg)
            .change_context(Error::DeploymentNotFound(deployment_name))
    }

    pub fn deployments(
        &self,
        start_after: Option<nonempty::String>,
        limit: u32,
    ) -> Result<Vec<ChainContractsResponse>, Error> {
        let msg = QueryMsg::Deployments { start_after, limit };
        self.client.query(&msg).change_context(Error::Deployments)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axelar_wasm_std::nonempty;
    use cosmwasm_std::testing::MockQuerier;
    use cosmwasm_std::{from_json, to_json_binary, Addr, QuerierWrapper, SystemError, WasmQuery};
    use router_api::{chain_name, cosmos_addr};

    use crate::client::Client;
    use crate::msg::{ChainContractsKey, ChainContractsResponse, QueryMsg};

    const AXELAR: &str = "axelar";
    const VERIFIER: &str = "verifier";

    #[test]
    fn query_ready_to_unbond_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.ready_to_unbond(cosmos_addr!(VERIFIER).to_string());

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_ready_to_unbond_returns_correct_result() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.ready_to_unbond(cosmos_addr!(VERIFIER).to_string());

        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_chain_contracts_returns_correct_result() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let res = client.chain_contracts(ChainContractsKey::ChainName(chain_name!(AXELAR)));
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());

        let res = client.chain_contracts(ChainContractsKey::GatewayAddress(Addr::unchecked(
            "gateway",
        )));
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());

        let res =
            client.chain_contracts(ChainContractsKey::ProverAddress(Addr::unchecked("prover")));
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());

        let res = client.chain_contracts(ChainContractsKey::VerifierAddress(Addr::unchecked(
            VERIFIER,
        )));
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_chain_contracts_name_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let res = client.chain_contracts(ChainContractsKey::ChainName(chain_name!(AXELAR)));
        assert!(res.is_err());
        goldie::assert_json!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_chain_contracts_gateway_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let res = client.chain_contracts(ChainContractsKey::GatewayAddress(
            Addr::unchecked("address").clone(),
        ));
        assert!(res.is_err());
        goldie::assert_json!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_chain_contracts_verifier_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let res = client.chain_contracts(ChainContractsKey::VerifierAddress(
            Addr::unchecked("address").clone(),
        ));
        assert!(res.is_err());
        goldie::assert_json!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_chain_contracts_prover_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let res = client.chain_contracts(ChainContractsKey::ProverAddress(
            Addr::unchecked("address").clone(),
        ));
        assert!(res.is_err());
        goldie::assert_json!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_deployment_returns_correct_result() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.deployment(nonempty::String::from_str(AXELAR).unwrap());

        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_deployments_returns_correct_results() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.deployments(None, 1);

        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        const ADDR: &str = "coordinator";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart {
                contract_addr,
                msg: _,
            } if contract_addr == cosmos_addr!(ADDR).as_str() => {
                Err(SystemError::Unknown {}).into() // simulate cryptic error seen in production
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, cosmos_addr!(ADDR))
    }

    fn setup_queries_to_succeed() -> (MockQuerier, Addr) {
        const ADDR: &str = "coordinator";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == cosmos_addr!(ADDR).as_str() =>
            {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::ReadyToUnbond {
                        verifier_address: _,
                    } => Ok(to_json_binary(&true).into()).into(),
                    QueryMsg::VerifierInfo {
                        service_name: _,
                        verifier: _,
                    } => Ok(to_json_binary(&true).into()).into(),
                    QueryMsg::ChainContractsInfo(_) => {
                        Ok(to_json_binary(&ChainContractsResponse {
                            chain_name: chain_name!(AXELAR),
                            prover_address: Addr::unchecked("prover"),
                            verifier_address: Addr::unchecked(VERIFIER),
                            gateway_address: Addr::unchecked("gateway"),
                        })
                        .into())
                        .into()
                    }
                    QueryMsg::Deployment { deployment_name: _ } => {
                        Ok(to_json_binary(&ChainContractsResponse {
                            chain_name: chain_name!(AXELAR),
                            prover_address: Addr::unchecked("prover"),
                            verifier_address: Addr::unchecked(VERIFIER),
                            gateway_address: Addr::unchecked("gateway"),
                        })
                        .into())
                        .into()
                    }
                    QueryMsg::Deployments {
                        start_after: _,
                        limit: _,
                    } => Ok(to_json_binary(&vec![ChainContractsResponse {
                        chain_name: chain_name!(AXELAR),
                        prover_address: Addr::unchecked("prover"),
                        verifier_address: Addr::unchecked(VERIFIER),
                        gateway_address: Addr::unchecked("gateway"),
                    }])
                    .into())
                    .into(),
                    _ => panic!("unexpected query: {:?}", msg),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, cosmos_addr!(ADDR))
    }
}
