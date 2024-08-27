use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::{Addr, HexBinary, WasmMsg};
use error_stack::{Result, ResultExt};
use router_api::{Address, ChainName, CrossChainId, Message};

use crate::msg::{ExecuteMsg, QueryMsg};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed to query the chain name at gateway contract {0}")]
    QueryChainName(Addr),
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
    pub fn call_contract(
        &self,
        destination_chain: ChainName,
        destination_address: Address,
        payload: HexBinary,
    ) -> WasmMsg {
        self.client.execute(&ExecuteMsg::CallContract {
            destination_chain,
            destination_address,
            payload,
        })
    }

    pub fn execute(&self, cc_id: CrossChainId, payload: HexBinary) -> WasmMsg {
        self.client.execute(&ExecuteMsg::Execute { cc_id, payload })
    }

    pub fn route_messages(&self, msgs: Vec<Message>) -> Option<WasmMsg> {
        msgs.to_none_if_empty()
            .map(|messages| self.client.execute(&ExecuteMsg::RouteMessages(messages)))
    }

    pub fn chain_name(&self) -> Result<ChainName, Error> {
        self.client
            .query(&QueryMsg::ChainName)
            .change_context_lazy(|| Error::QueryChainName(self.client.address.clone()))
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MockQuerier};
    use cosmwasm_std::{from_json, to_json_binary, Addr, DepsMut, QuerierWrapper, WasmQuery};

    use super::*;
    use crate::contract::{instantiate, query};
    use crate::msg::InstantiateMsg;

    #[test]
    fn chain_name() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::Client::new(QuerierWrapper::new(&querier), addr.clone()).into();

        assert_eq!(
            client.chain_name().unwrap(),
            ChainName::from_str("source-chain").unwrap()
        );
    }

    #[test]
    fn call_contract() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::Client::new(QuerierWrapper::new(&querier), addr.clone()).into();

        let destination_chain: ChainName = "destination-chain".parse().unwrap();
        let destination_address: Address = "destination-address".parse().unwrap();
        let payload = HexBinary::from(vec![1, 2, 3]);

        let msg = client.call_contract(
            destination_chain.clone(),
            destination_address.clone(),
            payload.clone(),
        );

        assert_eq!(
            msg,
            WasmMsg::Execute {
                contract_addr: addr.to_string(),
                msg: to_json_binary(&ExecuteMsg::CallContract {
                    destination_chain,
                    destination_address,
                    payload,
                })
                .unwrap(),
                funds: vec![],
            }
        );
    }

    #[test]
    fn execute_message() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::Client::new(QuerierWrapper::new(&querier), addr.clone()).into();

        let payload = HexBinary::from(vec![1, 2, 3]);
        let cc_id = CrossChainId::new("source-chain", "message-id").unwrap();

        let msg = client.execute(cc_id.clone(), payload.clone());

        assert_eq!(
            msg,
            WasmMsg::Execute {
                contract_addr: addr.to_string(),
                msg: to_json_binary(&ExecuteMsg::Execute { cc_id, payload }).unwrap(),
                funds: vec![],
            }
        );
    }

    fn setup() -> (MockQuerier, InstantiateMsg, Addr) {
        let addr = "axelarnet-gateway";
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
            chain_name: "source-chain".parse().unwrap(),
            router_address: "router".to_string(),
        };

        instantiate(deps, env, info, msg.clone()).unwrap();

        msg
    }
}
