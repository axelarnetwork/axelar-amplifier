pub mod execute_data;

use axelar_wasm_std::hash::Hash;
use error_stack::{Result, ResultExt};
use ethers_core::abi::{encode as abi_encode, Token, Tokenize};
use evm_gateway::{CommandType, Message, WeightedSigners};
use itertools::Itertools;
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};

use crate::error::ContractError;
use crate::payload::Payload;

impl From<&Payload> for CommandType {
    fn from(payload: &Payload) -> Self {
        match payload {
            Payload::Messages(_) => CommandType::ApproveMessages,
            Payload::VerifierSet(_) => CommandType::RotateSigners,
        }
    }
}

pub fn payload_hash_to_sign(
    domain_separator: &Hash,
    signer: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    let signer_hash = WeightedSigners::try_from(signer)
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

#[cfg(test)]
mod tests {
    use cosmwasm_std::HexBinary;

    use crate::encoding::abi::{payload_hash_to_sign, CommandType};
    use crate::payload::Payload;
    use crate::test::test_data::{
        curr_verifier_set, domain_separator, messages, new_verifier_set, verifier_set_from_pub_keys,
    };

    #[test]
    fn command_type_from_payload() {
        let payload = Payload::Messages(vec![]);
        assert_eq!(CommandType::from(&payload), CommandType::ApproveMessages);

        let payload = Payload::VerifierSet(new_verifier_set());
        assert_eq!(CommandType::from(&payload), CommandType::RotateSigners);
    }

    #[test]
    fn rotate_signers_message_hash() {
        let expected_hash =
            HexBinary::from_hex("fbb9a154bbafd0be9469d7c83bfe5807d916ec7430f5232f29b967240880f327")
                .unwrap();

        let domain_separator = domain_separator();

        let new_pub_keys = vec![
            "02de8b0cc10de1becab121cb1254a7b4075866b6e040d5a4cdd38c7ea6c68c7d0a",
            "025a08780e7b80e64511006ec4db4128e18b31f05e9c8a4ef285322991d5f17332",
            "03935a5be97cf2148cb5cb88d5f097a235859a572f46e53da907e80fd5578f9243",
            "02515a95a89320988ff96f5e990b6d4c0a6807072f9b01c9ae634cf846bae2bd08",
            "02464111b31e5d174ec44c172f5e3913d0a35344ef6c2cd8215494f23648ec3420",
        ];
        let new_verifier_set = verifier_set_from_pub_keys(new_pub_keys);

        let msg_to_sign = payload_hash_to_sign(
            &domain_separator,
            &curr_verifier_set(),
            &Payload::VerifierSet(new_verifier_set),
        )
        .unwrap();
        assert_eq!(msg_to_sign, expected_hash);
    }

    #[test]
    fn approve_messages_hash() {
        // generated by axelar-gmp-sdk-solidity unit tests
        let expected_hash =
            HexBinary::from_hex("58fec5536ad39d7992fd39cc75cf857f21aa2a9124b15faf328928fd635fd2e0")
                .unwrap();

        let domain_separator = domain_separator();

        let digest = payload_hash_to_sign(
            &domain_separator,
            &curr_verifier_set(),
            &Payload::Messages(messages()),
        )
        .unwrap();

        assert_eq!(digest, expected_hash);
    }
}
