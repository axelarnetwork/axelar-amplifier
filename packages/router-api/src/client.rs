use std::marker::PhantomData;

use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::{to_json_binary, Addr, CosmosMsg, Empty, WasmMsg};

use crate::msg::{ExecuteMsg, ExecuteMsgFromProxy};
use crate::primitives::{Address, ChainName};
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

    pub fn execute_from_contract(&self, original_sender: Addr, msg: &ExecuteMsg) -> CosmosMsg<T> {
        WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(&ExecuteMsgFromProxy::Relay {
                original_sender,
                msg: msg.clone(),
            })
            .expect("msg should always be serializable"),
            funds: vec![],
        }
        .into()
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
            &ExecuteMsg::RegisterChain {
                chain,
                gateway_address,
                msg_id_format,
            },
        )
    }
}
