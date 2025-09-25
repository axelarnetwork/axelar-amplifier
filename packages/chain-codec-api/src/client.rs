use cosmwasm_std::{Empty, HexBinary};
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
    pub fn payload_digest(
        &self,
        verifier_set: VerifierSet,
        payload: Payload,
    ) -> Result<HexBinary, Error> {
        let msg = QueryMsg::PayloadDigest {
            verifier_set,
            payload,
        };
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }

    #[cfg(feature = "receive-payload")]
    pub fn payload_digest(
        &self,
        verifier_set: VerifierSet,
        payload: Payload,
        full_message_payloads: Vec<HexBinary>,
    ) -> Result<HexBinary, Error> {
        let msg = QueryMsg::PayloadDigest {
            verifier_set,
            payload,
            full_message_payloads,
        };
        self.client
            .query(&msg)
            .change_context_lazy(|| Error::for_query(msg))
    }

    #[cfg(all(feature = "notify-signing-session", not(feature = "receive-payload")))]
    pub fn notify_signing_session(
        &self,
        multisig_session_id: cosmwasm_std::Uint64,
        verifier_set: VerifierSet,
        payload: Payload,
    ) -> cosmwasm_std::CosmosMsg {
        self.client.execute(&ExecuteMsg::NotifySigningSession {
            multisig_session_id,
            verifier_set,
            payload,
        })
    }

    #[cfg(all(feature = "notify-signing-session", feature = "receive-payload"))]
    pub fn notify_signing_session(
        &self,
        multisig_session_id: cosmwasm_std::Uint64,
        verifier_set: VerifierSet,
        payload: Payload,
        full_message_payloads: Vec<HexBinary>,
    ) -> cosmwasm_std::CosmosMsg {
        self.client.execute(&ExecuteMsg::NotifySigningSession {
            multisig_session_id,
            verifier_set,
            payload,
            full_message_payloads,
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
