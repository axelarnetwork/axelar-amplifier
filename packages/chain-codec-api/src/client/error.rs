use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::cw_serde;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use multisig_prover_api::payload::Payload;

use crate::msg::{FullMessagePayloads, QueryMsg};

#[derive(thiserror::Error)]
#[cw_serde]
pub enum ClientError {
    #[error("failed to encode execution data. verifier_set: {verifier_set:?}, signers: {signers:?}, payload: {payload:?}")]
    EncodeExecData {
        domain_separator: Hash,
        verifier_set: VerifierSet,
        signers: Vec<SignerWithSig>,
        payload: Payload,
    },
    #[error("failed to validate address: {address}")]
    ValidateAddress { address: String },
    #[error("failed to get payload digest. signer: {signer:?}, payload: {payload:?}, full_message_payloads: {full_message_payloads:?}")]
    PayloadDigest {
        domain_separator: Hash,
        signer: VerifierSet,
        payload: Payload,
        full_message_payloads: FullMessagePayloads,
    },
}

impl ClientError {
    pub fn for_query(value: QueryMsg) -> Self {
        match value {
            QueryMsg::EncodeExecData {
                domain_separator,
                verifier_set,
                signers,
                payload,
            } => ClientError::EncodeExecData {
                domain_separator,
                verifier_set,
                signers,
                payload,
            },
            QueryMsg::ValidateAddress { address } => ClientError::ValidateAddress { address },
            QueryMsg::PayloadDigest {
                domain_separator,
                verifier_set: signer,
                payload,
                full_message_payloads,
            } => ClientError::PayloadDigest {
                domain_separator,
                signer,
                payload,
                full_message_payloads,
            },
        }
    }
}
