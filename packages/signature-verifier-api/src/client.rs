use cosmwasm_schema::serde::de::DeserializeOwned;
use cosmwasm_std::{CosmosMsg, HexBinary, Uint64};
use error_stack::{Result, ResultExt};

use crate::msg::{ExecuteMsg, QueryMsg};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not query the signature verifier contract with {signature:?}, {message:?}, {public_key:?}, {signer_address:?}, {session_id:?}")]
    VerifySignature {
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    },
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::VerifySignature { signature, message, public_key, signer_address, session_id } => {
                Error::VerifySignature { signature, message, public_key, signer_address, session_id }
            },
        }
    }
}

pub struct SignatureVerifier<'a> {
    client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for SignatureVerifier<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        SignatureVerifier { client }
    }
}

impl<'a> SignatureVerifier<'a> {
    pub fn verify_signature(
        &self,
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::VerifySignature {
            signature,
            message,
            public_key,
            signer_address,
            session_id,
        })
    }

    fn query<U: DeserializeOwned + 'static>(&self, msg: QueryMsg) -> Result<U, Error> {
        self.client
            .query(&msg)
            .change_context_lazy(|| msg.into())
    }

    pub fn verify_signature_query(
        &self,
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    ) -> Result<bool, Error> {
        self.query(QueryMsg::VerifySignature {
            signature,
            message,
            public_key,
            signer_address,
            session_id,
        })
    }
}
