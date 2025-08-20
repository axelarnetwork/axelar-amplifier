use cosmwasm_std::{CosmosMsg, Empty, HexBinary, Uint64};
use error_stack::{Result, ResultExt};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use multisig_prover_api::payload::Payload;

use crate::error::Error;
use crate::msg::{ExecuteMsg, QueryMsg};

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl Client<'_> {
    #[cfg(not(feature = "receive-payload"))]
    pub fn payload_digest(&self, signer: VerifierSet, payload: Payload) -> Result<HexBinary, Error> {
        let msg = QueryMsg::PayloadDigest { signer, payload };
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }

    #[cfg(feature = "receive-payload")]
    pub fn payload_digest(
        &self,
        signer: VerifierSet,
        payload: Payload,
        payload_bytes: Vec<HexBinary>,
    ) -> Result<HexBinary, Error> {
        let msg = QueryMsg::PayloadDigest { signer, payload, payload_bytes };
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }

    #[cfg(not(feature = "receive-payload"))]
    pub fn notify_signing_session(
        &self,
        multisig_session_id: Uint64,
        verifier_set: VerifierSet,
        payload: Payload,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::NotifySigningSession {
            multisig_session_id,
            verifier_set,
            payload,
        })
    }

    #[cfg(feature = "receive-payload")]
    pub fn notify_signing_session(
        &self,
        multisig_session_id: Uint64,
        verifier_set: VerifierSet,
        payload: Payload,
        payload_bytes: Vec<HexBinary>,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::NotifySigningSession {
            multisig_session_id,
            verifier_set,
            payload,
            payload_bytes,
        })
    }

    pub fn encode_exec_data(
        &self,
        verifier_set: VerifierSet,
        signers: Vec<SignerWithSig>,
        payload: Payload,
    ) -> Result<HexBinary, Error> {
        let msg = QueryMsg::EncodeExecData {
            verifier_set,
            signers,
            payload,
        };
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }

    pub fn validate_address(&self, address: String) -> Result<Empty, Error> {
        let msg = QueryMsg::ValidateAddress { address };
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }
}
