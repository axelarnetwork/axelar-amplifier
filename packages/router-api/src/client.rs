use std::marker::PhantomData;

use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::{to_json_binary, Addr, CosmosMsg, Empty, WasmMsg};

use crate::error::Error;
use crate::msg::ExecuteMsg;
use crate::Message;
use crate::primitives::{Address, ChainName};

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

    fn execute(&self, msg: &ExecuteMsg) -> Result<CosmosMsg<T>, Error> {
        Ok(WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(&msg).map_err(|_| Error::Serialize)?,
            funds: vec![],
        }
        .into())
    }

    pub fn route(&self, msgs: Vec<Message>) -> Option<CosmosMsg<T>> {
        match msgs
            .to_none_if_empty()
            .map(|msgs| self.execute(&ExecuteMsg::RouteMessages(msgs)))
            .transpose()
        {
            Ok(m) => m,
            Err(_) => None,
        }
    }

    pub fn execute_from_contract(&self, original_sender: Addr, msg: &ExecuteMsg) -> Result<CosmosMsg<T>, Error> {
        Ok(WasmMsg::Execute {
            contract_addr: original_sender.to_string(),
            msg: to_json_binary(&msg).map_err(|_| Error::Serialize)?,
            funds: vec![],
        }
        .into())
    }

    pub fn register_deployment(
        &self,
        original_sender: Addr,
        chain: ChainName,
        gateway_address: Address,
        msg_id_format: MessageIdFormat,
    ) -> Option<CosmosMsg<T>> {
        match self.execute_from_contract(original_sender, &ExecuteMsg::RegisterChain {
            chain,
            gateway_address,
            msg_id_format,
        }) {
            Ok(m) => Some(m),
            Err(_) => None,
        }
    }
}
