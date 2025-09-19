use axelar_wasm_std::hash::Hash;
use cosmwasm_std::{Empty, HexBinary};
pub use error::ClientError;
use error_stack::{Result, ResultExt};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use multisig_prover_api::payload::Payload;

use crate::msg::{ExecuteMsg, QueryMsg};

mod error;

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl Client<'_> {
    pub fn payload_digest(
        &self,
        domain_separator: Hash,
        verifier_set: VerifierSet,
        payload: Payload,
        full_message_payloads: Vec<HexBinary>,
    ) -> Result<HexBinary, ClientError> {
        let msg = QueryMsg::PayloadDigest {
            domain_separator,
            verifier_set,
            payload,
            full_message_payloads,
        };
        self.client
            .query(&msg)
            .change_context_lazy(|| ClientError::for_query(msg))
    }

    pub fn notify_signing_session(
        &self,
        domain_separator: Hash,
        multisig_session_id: cosmwasm_std::Uint64,
        verifier_set: VerifierSet,
        payload: Payload,
        full_message_payloads: Vec<HexBinary>,
    ) -> cosmwasm_std::CosmosMsg {
        self.client.execute(&ExecuteMsg::NotifySigningSession {
            domain_separator,
            multisig_session_id,
            verifier_set,
            payload,
            full_message_payloads,
        })
    }

    pub fn encode_exec_data(
        &self,
        domain_separator: Hash,
        verifier_set: VerifierSet,
        signers: Vec<SignerWithSig>,
        payload: Payload,
    ) -> Result<HexBinary, ClientError> {
        let msg = QueryMsg::EncodeExecData {
            domain_separator,
            verifier_set,
            signers,
            payload,
        };
        self.client
            .query(&msg)
            .change_context_lazy(|| ClientError::for_query(msg))
    }

    pub fn validate_address(&self, address: String) -> Result<Empty, ClientError> {
        let msg = QueryMsg::ValidateAddress { address };
        self.client
            .query(&msg)
            .change_context_lazy(|| ClientError::for_query(msg))
    }
}
