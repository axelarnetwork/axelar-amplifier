use std::marker::PhantomData;

use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::{to_json_binary, Addr, CosmosMsg, Empty, WasmMsg};

use crate::msg::ExecuteMsg;
use crate::Message;

pub struct Router<T = Empty> {
    pub address: Addr,
    custom_msg_type: PhantomData<T>,
}

impl<T> Router<T> {
    pub fn new(address: Addr) -> Self {
        Router {
            address,
            custom_msg_type: PhantomData,
        }
    }

    fn execute(&self, msg: &ExecuteMsg) -> CosmosMsg<T> {
        WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(&msg).expect("msg should always be serializable"),
            funds: vec![],
        }
        .into()
    }

    pub fn route(&self, msgs: Vec<Message>) -> Option<CosmosMsg<T>> {
        msgs.to_none_if_empty()
            .map(|msgs| self.execute(&ExecuteMsg::RouteMessages(msgs)))
    }
}
