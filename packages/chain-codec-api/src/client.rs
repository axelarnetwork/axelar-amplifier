use cosmwasm_std::{CosmosMsg, Empty, HexBinary};
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
    pub fn payload_digest(&self, signer: VerifierSet, payload: Payload) -> CosmosMsg {
        self.client
            .execute(&ExecuteMsg::PayloadDigest { signer, payload })
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
