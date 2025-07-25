use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::{Coin, CosmosMsg, HexBinary};
use error_stack::Result;
use router_api::{Address, ChainName, CrossChainId, Message};

use crate::msg::{ExecuteMsg, QueryMsg};

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl Client<'_> {
    pub fn call_contract(
        &self,
        destination_chain: ChainName,
        destination_address: Address,
        payload: HexBinary,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::CallContract {
            destination_chain,
            destination_address,
            payload,
        })
    }

    pub fn call_contract_with_token(
        &self,
        destination_chain: ChainName,
        destination_address: Address,
        payload: HexBinary,
        coin: Coin,
    ) -> CosmosMsg {
        self.client.execute_with_funds(
            &ExecuteMsg::CallContract {
                destination_chain,
                destination_address,
                payload,
            },
            coin,
        )
    }

    pub fn execute(&self, cc_id: CrossChainId, payload: HexBinary) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::Execute { cc_id, payload })
    }

    pub fn route_messages(&self, msgs: Vec<Message>) -> Option<CosmosMsg> {
        msgs.to_none_if_empty()
            .map(|messages| self.client.execute(&ExecuteMsg::RouteMessages(messages)))
    }

    pub fn chain_name(&self) -> Result<ChainName, client::Error> {
        self.client.query(&QueryMsg::ChainName)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env, MockQuerier};
    use cosmwasm_std::{from_json, to_json_binary, Addr, QuerierWrapper, WasmMsg, WasmQuery};

    use super::*;
    use crate::contract::{instantiate, query};
    use crate::msg::InstantiateMsg;

    #[test]
    fn chain_name() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        assert_eq!(
            client.chain_name().unwrap(),
            ChainName::from_str("source-chain").unwrap()
        );
    }

    #[test]
    fn call_contract() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

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
            .into()
        );
    }

    #[test]
    fn execute_message() {
        let (querier, _, addr) = setup();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

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
            .into()
        );
    }

    fn setup() -> (MockQuerier, InstantiateMsg, Addr) {
        let mut deps = mock_dependencies();
        let addr = deps.api.addr_make("axelarnet-gateway");
        let addr_clone = addr.clone();
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("deployer"), &[]);

        let instantiate_msg = InstantiateMsg {
            chain_name: "source-chain".parse().unwrap(),
            router_address: deps.api.addr_make("router").to_string(),
            nexus: deps.api.addr_make("nexus").to_string(),
        };

        instantiate(deps.as_mut(), env, info, instantiate_msg.clone()).unwrap();

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr.as_str() => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                Ok(query(deps.as_ref(), mock_env(), msg).into()).into()
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, instantiate_msg, addr_clone)
    }
}
