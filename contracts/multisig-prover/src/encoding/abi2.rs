use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use error_stack::{Result, ResultExt};
use ethers_contract::contract::EthCall;
use ethers_core::abi::{encode as abi_encode, Token, Tokenize};
use evm_gateway::{
    ApproveMessagesCall, CommandType, Message, Proof, RotateSignersCall, WeightedSigners,
};
use itertools::Itertools;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};

use crate::encoding::{to_recoverable, Encoder2};
use crate::error::ContractError;
use crate::payload::Payload;
use crate::Encoder;

pub(crate) struct AbiEncoder;

impl Encoder2 for AbiEncoder {
    fn digest(
        domain_separator: &Hash,
        verifier_set: &VerifierSet,
        payload: &Payload,
    ) -> Result<Hash, ContractError> {
        let signer_hash = WeightedSigners::try_from(verifier_set)
            .map(|signers| signers.hash())
            .change_context(ContractError::InvalidVerifierSet)?;

        let data_hash = Keccak256::digest(encode(payload)?);

        // Prefix for standard EVM signed data https://eips.ethereum.org/EIPS/eip-191
        let unsigned = [
            "\x19Ethereum Signed Message:\n96".as_bytes(),
            domain_separator,
            signer_hash.as_slice(),
            data_hash.as_slice(),
        ]
        .concat();

        Ok(Keccak256::digest(unsigned).into())
    }

    fn execute_data(
        &self,
        domain_separator: &Hash,
        verifier_set: &VerifierSet,
        signatures: Vec<SignerWithSig>,
        payload: &Payload,
    ) -> Result<HexBinary, ContractError> {
        let payload_digest = Self::digest(domain_separator, verifier_set, payload)?;
        let signers = to_recoverable(Encoder::Abi, payload_digest, signatures);

        let proof = Proof::new(verifier_set, signers).change_context(ContractError::Proof)?;

        let (selector, encoded) = match payload {
            Payload::Messages(messages) => {
                let messages: Vec<_> = messages
                    .iter()
                    .map(Message::try_from)
                    .collect::<Result<_, _>>()
                    .change_context(ContractError::InvalidMessage)?;

                (
                    ApproveMessagesCall::selector(),
                    abi_encode(&ApproveMessagesCall { messages, proof }.into_tokens()),
                )
            }
            Payload::VerifierSet(new_verifier_set) => {
                let new_signers = WeightedSigners::try_from(new_verifier_set)
                    .change_context(ContractError::InvalidVerifierSet)?;

                (
                    RotateSignersCall::selector(),
                    abi_encode(&RotateSignersCall { new_signers, proof }.into_tokens()),
                )
            }
        };

        Ok(selector
            .into_iter()
            .chain(encoded)
            .collect::<Vec<_>>()
            .into())
    }
}

pub fn encode(payload: &Payload) -> Result<Vec<u8>, ContractError> {
    let command_type = CommandType::from(payload).into();

    match payload {
        Payload::Messages(messages) => {
            let messages = messages
                .iter()
                .map(Message::try_from)
                .map_ok(|m| Token::Tuple(m.into_tokens()))
                .collect::<Result<Vec<_>, _>>()
                .change_context(ContractError::InvalidMessage)?;

            Ok(abi_encode(&[command_type, Token::Array(messages)]))
        }
        Payload::VerifierSet(verifier_set) => Ok(abi_encode(&[
            command_type,
            Token::Tuple(
                WeightedSigners::try_from(verifier_set)
                    .change_context(ContractError::InvalidVerifierSet)?
                    .into_tokens(),
            ),
        ])),
    }
}
