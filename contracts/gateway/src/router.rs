use cosmwasm_std::{to_binary, Addr, WasmMsg};

pub(crate) struct Router {
    pub address: Addr,
}

impl Router {
    fn execute(&self, msg: &connection_router::msg::ExecuteMsg) -> WasmMsg {
        WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_binary(&msg).expect("msg should always be serializable"),
            funds: vec![],
        }
    }

    pub(crate) fn route_messages(&self, msgs: Vec<connection_router::Message>) -> WasmMsg {
        self.execute(&connection_router::msg::ExecuteMsg::RouteMessages(msgs))
    }
}
