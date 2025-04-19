use std::collections::HashSet;

use cosmwasm_std::{Addr, CosmosMsg};
use error_stack::{Result, ResultExt};
use router_api::ChainName;

use crate::msg::{ChainContractsKey, ChainContractsResponse, ExecuteMsg, QueryMsg};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error(
        "failed to execute ReadyToUnbond query at coordinator contract. verifier_address: {0}"
    )]
    ReadyToUnbond(String),

    #[error(
        "failed to execute VerifierDetailsWithProvers query at coordinator contract. service_name: {service_name}, verifier_address: {verifier_address}"
    )]
    VerifierDetailsWithProvers {
        service_name: String,
        verifier_address: String,
    },

    #[error("failed to execute ChainContractsInfo query at coordinator contract. chain name {0}")]
    ChainNameNotRegistered(String),

    #[error("failed to execute ChainContractsInfo query at coordinator contract. gateway {0}")]
    GatewayNotRegistered(Addr),

    #[error("failed to execute ChainContractsInfo query at coordinator contract. prover {0}")]
    ProverNotRegistered(Addr),

    #[error("failed to execute ChainContractsInfo query at coordinator contract. verifier {0}")]
    VerifierNotRegistered(Addr),
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::ReadyToUnbond { verifier_address } => Error::ReadyToUnbond(verifier_address),
            QueryMsg::VerifierInfo {
                service_name,
                verifier,
            } => Error::VerifierDetailsWithProvers {
                service_name,
                verifier_address: verifier,
            },
            QueryMsg::ChainContractsInfo(chain_contracts_key) => match chain_contracts_key {
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
    pub fn register_prover_contract(
        &self,
        chain_name: ChainName,
        new_prover_addr: String,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::RegisterProverContract {
            chain_name,
            new_prover_addr,
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
        let msg = QueryMsg::ReadyToUnbond { verifier_address };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn chain_contracts(
        &self,
        chain_contracts_key: ChainContractsKey,
    ) -> Result<ChainContractsResponse, Error> {
        let msg = QueryMsg::ChainContractsInfo(chain_contracts_key);
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use cosmwasm_std::testing::{MockApi, MockQuerier};
    use cosmwasm_std::{from_json, to_json_binary, Addr, QuerierWrapper, SystemError, WasmQuery};

    use crate::client::Client;
    use crate::msg::{ChainContractsKey, ChainContractsResponse, QueryMsg};

    #[test]
    fn query_ready_to_unbond_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.ready_to_unbond(MockApi::default().addr_make("verifier").to_string());

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_ready_to_unbond_returns_correct_result() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.ready_to_unbond(MockApi::default().addr_make("verifier").to_string());

        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_chain_contracts_returns_correct_result() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let res = client.chain_contracts(ChainContractsKey::ChainName(
            router_api::ChainName::from_str("axelar").unwrap(),
        ));
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
            "verifier",
        )));
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_chain_contracts_name_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let res = client.chain_contracts(ChainContractsKey::ChainName(
            router_api::ChainName::from_str("axelar").unwrap(),
        ));
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

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        let addr = "coordinator";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart {
                contract_addr,
                msg: _,
            } if contract_addr == MockApi::default().addr_make(addr).as_str() => {
                Err(SystemError::Unknown {}).into() // simulate cryptic error seen in production
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, MockApi::default().addr_make(addr))
    }

    fn setup_queries_to_succeed() -> (MockQuerier, Addr) {
        let addr = "coordinator";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == MockApi::default().addr_make(addr).as_str() =>
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
                            chain_name: router_api::ChainName::from_str("axelar").unwrap(),
                            prover_address: Addr::unchecked("prover"),
                            verifier_address: Addr::unchecked("verifier"),
                            gateway_address: Addr::unchecked("gateway"),
                        })
                        .into())
                        .into()
                    }
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, MockApi::default().addr_make(addr))
    }
}
