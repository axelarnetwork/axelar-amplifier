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
    #[error("failed to get payload digest. verifier_set: {verifier_set:?}, payload: {payload:?}, full_message_payloads: {full_message_payloads:?}")]
    PayloadDigest {
        domain_separator: Hash,
        verifier_set: VerifierSet,
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
                verifier_set,
                payload,
                full_message_payloads,
            } => ClientError::PayloadDigest {
                domain_separator,
                verifier_set,
                payload,
                full_message_payloads,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use multisig::key::PublicKey;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use multisig_prover_api::payload::Payload;

    use super::*;

    fn dummy_verifier_set() -> VerifierSet {
        let mut signers = BTreeMap::new();
        signers.insert(
            "signer".to_string(),
            Signer {
                address: Addr::unchecked("signer"),
                weight: Uint128::one(),
                pub_key: PublicKey::Ecdsa(HexBinary::from(&[1u8; 33][..])),
            },
        );
        VerifierSet {
            signers,
            threshold: Uint128::one(),
            created_at: 1,
        }
    }

    #[test]
    fn for_query_payload_digest() {
        let query = QueryMsg::PayloadDigest {
            domain_separator: [0u8; 32],
            verifier_set: dummy_verifier_set(),
            payload: Payload::Messages(vec![]),
            full_message_payloads: FullMessagePayloads::NotSupported,
        };

        let err = ClientError::for_query(query);
        assert!(matches!(err, ClientError::PayloadDigest { .. }));
    }
}
