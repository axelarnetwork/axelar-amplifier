use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::{to_json_binary, Addr, WasmMsg};

use crate::msg::ExecuteMsg;
use crate::Message;

pub struct Router {
    pub address: Addr,
}

impl Router {
    fn execute(&self, msg: &ExecuteMsg) -> WasmMsg {
        WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(&msg).expect("msg should always be serializable"),
            funds: vec![],
        }
    }

    pub fn route(&self, msgs: Vec<Message>) -> Option<WasmMsg> {
        msgs.to_none_if_empty()
            .map(|msgs| self.execute(&ExecuteMsg::RouteMessages(msgs)))
    }
}
