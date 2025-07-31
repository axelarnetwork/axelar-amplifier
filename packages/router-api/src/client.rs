use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::{Addr, CosmosMsg};

use crate::msg::{ExecuteMsg, QueryMsg};
use crate::primitives::{Address, ChainName};
use crate::Message;

pub struct Client<'a> {
    pub client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

impl Client<'_> {
    pub fn route(&self, msgs: Vec<Message>) -> Option<CosmosMsg> {
        msgs.to_none_if_empty()
            .map(|msgs| self.client.execute(&ExecuteMsg::RouteMessages(msgs)))
    }

    pub fn register_chain(
        &self,
        original_sender: Addr,
        chain: ChainName,
        gateway_address: Address,
        msg_id_format: MessageIdFormat,
    ) -> CosmosMsg {
        self.client.execute_as_proxy(
            original_sender,
            ExecuteMsg::RegisterChain {
                chain,
                gateway_address,
                msg_id_format,
            },
        )
    }
}
