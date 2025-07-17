use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::cw_serde;
use multisig::{msg::SignerWithSig, verifier_set::VerifierSet};
use multisig_prover_api::payload::Payload;

use crate::msg::QueryMsg;


#[derive(thiserror::Error)]
#[cw_serde]
pub enum Error {
    #[error("failed to compute payload digest. domain_separator: {domain_separator:?}, signer: {signer:?}, payload: {payload:?}")]
    PayloadDigest {
        domain_separator: Hash,
        signer: VerifierSet,
        payload: Payload,
    },
    #[error("failed to encode execution data. domain_separator: {domain_separator:?}, verifier_set: {verifier_set:?}, signers: {signers:?}, payload: {payload:?}")]
    EncodeExecData {
        domain_separator: Hash,
        verifier_set: VerifierSet,
        signers: Vec<SignerWithSig>,
        payload: Payload,
    },
    #[error("failed to validate address: {address}")]
    ValidateAddress {
        address: String,
    }
}


impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::PayloadDigest { domain_separator, signer, payload } => {
                Error::PayloadDigest { domain_separator, signer, payload }
            }
            QueryMsg::EncodeExecData { domain_separator, verifier_set, signers, payload } => {
                Error::EncodeExecData { domain_separator, verifier_set, signers, payload }
            }
            QueryMsg::ValidateAddress { address } => Error::ValidateAddress { address },
        }
    }
}