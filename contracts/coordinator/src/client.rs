use std::collections::HashSet;

use cosmwasm_std::{Addr, WasmMsg};
use error_stack::{Result, ResultExt};
use router_api::ChainName;

use crate::msg::{ExecuteMsg, QueryMsg};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed to execute ReadyToUnbond query at coordinator contract. worker_address: {0}")]
    ReadyToUnbond(Addr),
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::ReadyToUnbond { worker_address } => Error::ReadyToUnbond(worker_address),
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
    pub fn register_prover_contract(
        &self,
        chain_name: ChainName,
        new_prover_addr: Addr,
    ) -> WasmMsg {
        self.client.execute(&ExecuteMsg::RegisterProverContract {
            chain_name,
            new_prover_addr,
        })
    }

    pub fn set_active_verifiers(&self, verifiers: HashSet<Addr>) -> WasmMsg {
        self.client
            .execute(&ExecuteMsg::SetActiveVerifiers { verifiers })
    }

    pub fn ready_to_unbond(&self, worker_address: Addr) -> Result<bool, Error> {
        let msg = QueryMsg::ReadyToUnbond { worker_address };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}

#[cfg(test)]
mod test {

    use cosmwasm_std::testing::MockQuerier;
    use cosmwasm_std::{from_json, to_json_binary, Addr, QuerierWrapper, SystemError, WasmQuery};

    use crate::client::Client;
    use crate::msg::QueryMsg;

    #[test]
    fn query_ready_to_unbond_returns_error_when_query_fails() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.ready_to_unbond(Addr::unchecked("worker"));

        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_ready_to_unbond_returns_correct_result() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client = client::Client::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.ready_to_unbond(Addr::unchecked("worker"));

        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        let addr = "coordinator";

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
        let addr = "coordinator";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::ReadyToUnbond { worker_address: _ } => {
                        Ok(to_json_binary(&true).into()).into()
                    }
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, Addr::unchecked(addr))
    }
}
