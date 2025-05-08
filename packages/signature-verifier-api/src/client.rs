use std::marker::PhantomData;

use cosmwasm_schema::serde::de::DeserializeOwned;
use cosmwasm_std::{
    to_json_binary, Addr, CosmosMsg, Empty, HexBinary, QuerierWrapper, QueryRequest, Uint64,
    WasmMsg, WasmQuery,
};
use error_stack::{Result, ResultExt};

use crate::msg::{ExecuteMsg, QueryMsg};

#[derive(Clone)]
pub struct SignatureVerifier<'a, T = Empty> {
    pub address: Addr,
    pub querier: QuerierWrapper<'a>,
    custom_msg_type: PhantomData<T>,
}

impl<'a, T> SignatureVerifier<'a, T> {
    pub fn new(address: Addr, querier: QuerierWrapper<'a>) -> Self {
        SignatureVerifier::<'a, T> {
            address,
            querier,
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

    pub fn verify_signature_exec(
        &self,
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    ) -> CosmosMsg<T> {
        self.execute(&ExecuteMsg::VerifySignature {
            signature,
            message,
            public_key,
            signer_address,
            session_id,
        })
    }

    fn query<U: DeserializeOwned + 'static>(&self, msg: &QueryMsg) -> Result<U, Error> {
        self.querier
            .query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: self.address.to_string(),
                msg: to_json_binary(msg).expect("msg should always be serializable"),
            }))
            .change_context(Error::QuerySignatureVerifier)
    }

    pub fn verify_signature(
        &self,
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    ) -> Result<bool, Error> {
        self.query(&QueryMsg::VerifySignature {
            signature,
            message,
            public_key,
            signer_address,
            session_id,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not query the signature verifier contract")]
    QuerySignatureVerifier,
}
