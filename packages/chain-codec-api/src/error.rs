use cosmwasm_schema::cw_serde;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use multisig_prover_api::payload::Payload;

use crate::msg::QueryMsg;

#[derive(thiserror::Error)]
#[cw_serde]
pub enum Error {
    #[error("failed to encode execution data. verifier_set: {verifier_set:?}, signers: {signers:?}, payload: {payload:?}")]
    EncodeExecData {
        verifier_set: VerifierSet,
        signers: Vec<SignerWithSig>,
        payload: Payload,
    },
    #[error("failed to validate address: {address}")]
    ValidateAddress { address: String },
    #[cfg_attr(
        not(feature = "receive-payload"),
        error("failed to get payload digest. signer: {signer:?}, payload: {payload:?}")
    )]
    #[cfg_attr(
        feature = "receive-payload",
        error("failed to get payload digest. signer: {signer:?}, payload: {payload:?}, payload_bytes: {payload_bytes:?}")
    )]
    PayloadDigest {
        signer: VerifierSet,
        payload: Payload,
        #[cfg(feature = "receive-payload")]
        payload_bytes: Vec<cosmwasm_std::HexBinary>,
    },
}

impl Error {
    pub fn for_query(value: QueryMsg) -> Self {
        match value {
            QueryMsg::EncodeExecData {
                verifier_set,
                signers,
                payload,
            } => Error::EncodeExecData {
                verifier_set,
                signers,
                payload,
            },
            QueryMsg::ValidateAddress { address } => Error::ValidateAddress { address },
            QueryMsg::PayloadDigest {
                verifier_set: signer,
                payload,
                #[cfg(feature = "receive-payload")]
                payload_bytes,
            } => Error::PayloadDigest {
                signer,
                payload,
                #[cfg(feature = "receive-payload")]
                payload_bytes,
            },
        }
    }
}
