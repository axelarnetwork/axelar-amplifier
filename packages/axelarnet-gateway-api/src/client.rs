use cosmwasm_std::{to_json_binary, Addr, HexBinary, WasmMsg};
use router_api::{Address, ChainName, Message};

use crate::msg::ExecuteMsg;

pub struct AxelarnetGateway {
    pub address: Addr,
}

impl AxelarnetGateway {
    fn execute(&self, msg: &ExecuteMsg) -> WasmMsg {
        WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(&msg).expect("msg should always be serializable"),
            funds: vec![],
        }
    }

    pub fn call_contract(
        &self,
        destination_chain: ChainName,
        destination_address: Address,
        payload: HexBinary,
    ) -> WasmMsg {
        self.execute(&ExecuteMsg::CallContract {
            destination_chain,
            destination_address,
            payload,
        })
    }

    pub fn validate_message(&self, message: Message) -> WasmMsg {
        self.execute(&ExecuteMsg::ValidateMessage(message))
    }
}
