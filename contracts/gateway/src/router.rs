use crate::error::ContractError;
use cosmwasm_std::{to_binary, Addr, WasmMsg};
use error_stack::ResultExt;

pub struct RouterApi {
    pub address: Addr,
}

impl RouterApi {
    pub fn execute(
        &self,
        msg: &connection_router::msg::ExecuteMsg,
    ) -> error_stack::Result<WasmMsg, ContractError> {
        Ok(WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_binary(&msg).change_context(ContractError::CreateRouterExecuteMsg)?,
            funds: vec![],
        })
    }
}
