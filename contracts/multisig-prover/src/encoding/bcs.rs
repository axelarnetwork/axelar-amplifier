use std::iter;

use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use error_stack::{Result, ResultExt};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};
use sui_gateway::gateway::{
    ExecuteData, Message, MessageToSign, Proof, WeightedSigners, COMMAND_TYPE_APPROVE_MESSAGES,
    COMMAND_TYPE_ROTATE_SIGNERS,
};

use crate::encoding::{to_recoverable, Encoder};
use crate::error::ContractError;
use crate::payload::Payload;

fn encode_payload(payload: &Payload) -> Result<Vec<u8>, ContractError> {
    let encoded: Vec<u8> = match payload {
        Payload::Messages(messages) => bcs::to_bytes(
            &messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<Vec<_>, _>>()
                .change_context(ContractError::InvalidMessage)?,
        )
        .expect("failed to serialize messages"),
        Payload::VerifierSet(verifier_set) => {
            bcs::to_bytes(&WeightedSigners::from(verifier_set.clone()))
                .expect("failed to weighted signers")
        }
    };

    Ok(encoded)
}

pub fn payload_digest(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    let command_type = match payload {
        Payload::Messages(_) => COMMAND_TYPE_APPROVE_MESSAGES,
        Payload::VerifierSet(_) => COMMAND_TYPE_ROTATE_SIGNERS,
    };
    let data = iter::once(command_type)
        .chain(encode_payload(payload)?)
        .collect::<Vec<_>>();
    let msg = MessageToSign {
        domain_separator: (*domain_separator).into(),
        signers_hash: WeightedSigners::from(verifier_set.clone()).hash().into(),
        data_hash: <[u8; 32]>::from(Keccak256::digest(data)).into(),
    };

    Ok(msg.hash())
}

pub fn encode_execute_data(
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
    payload_digest: &Hash,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let signatures = to_recoverable(Encoder::Bcs, payload_digest, signatures);

    let encoded_payload = encode_payload(payload)?;
    let encoded_proof = bcs::to_bytes(&Proof::new(verifier_set.clone(), signatures.clone()))
        .expect("failed to serialize proof");
    let execute_data = ExecuteData::new(encoded_payload, encoded_proof);

    Ok(bcs::to_bytes(&execute_data)
        .expect("failed to serialize execute data")
        .into())
}
