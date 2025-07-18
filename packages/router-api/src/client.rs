use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::{Addr, CosmosMsg, Empty};

use crate::msg::{ExecuteMsg, ExecuteMsgFromProxy, QueryMsg};
use crate::primitives::{Address, ChainName};
use crate::Message;

pub struct Client<'a, T = Empty> {
    pub client: client::ContractClient<'a, ExecuteMsgFromProxy, QueryMsg, T>,
}

impl<'a, T> From<client::ContractClient<'a, ExecuteMsgFromProxy, QueryMsg, T>> for Client<'a, T> {
    fn from(client: client::ContractClient<'a, ExecuteMsgFromProxy, QueryMsg, T>) -> Self {
        Client { client }
    }
}

impl<'a, T> Client<'a, T> {
    pub fn route(&self, msgs: Vec<Message>) -> Option<CosmosMsg<T>> {
        msgs.to_none_if_empty()
            .map(|msgs| self.client.execute(&ExecuteMsg::RouteMessages(msgs).into()))
    }

    pub fn execute_from_contract(&self, original_sender: Addr, msg: ExecuteMsg) -> CosmosMsg<T> {
        self.client.execute(&ExecuteMsgFromProxy::Relay {
            sender: original_sender,
            msg,
        })
    }

    pub fn register_chain(
        &self,
        original_sender: Addr,
        chain: ChainName,
        gateway_address: Address,
        msg_id_format: MessageIdFormat,
    ) -> CosmosMsg<T> {
        self.execute_from_contract(
            original_sender,
            ExecuteMsg::RegisterChain {
                chain,
                gateway_address,
                msg_id_format,
            },
        )
    }
}
