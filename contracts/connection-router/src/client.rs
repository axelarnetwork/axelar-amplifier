use crate::msg::ExecuteMsg;
use crate::Message;
use cosmwasm_std::{to_binary, Addr, WasmMsg};

pub struct Router {
    pub address: Addr,
}

impl Router {
    fn execute(&self, msg: &ExecuteMsg) -> WasmMsg {
        WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_binary(&msg).expect("msg should always be serializable"),
            funds: vec![],
        }
    }

    pub fn route(&self, msgs: Vec<Message>) -> Option<WasmMsg> {
        ignore_empty(msgs).map(|msgs| self.execute(&ExecuteMsg::RouteMessages(msgs)))
    }
}

// TODO: unify across contract clients
fn ignore_empty(msgs: Vec<Message>) -> Option<Vec<Message>> {
    if msgs.is_empty() {
        None
    } else {
        Some(msgs)
    }
}
