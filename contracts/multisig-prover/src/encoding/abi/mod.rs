pub mod execute_data;

use std::str::FromStr;

use alloy_primitives::{Address, FixedBytes};
use alloy_sol_types::{sol, SolValue};
use cosmwasm_std::Uint256;
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use sha3::{Digest, Keccak256};

use axelar_wasm_std::hash::Hash;
use multisig::{key::PublicKey as MultisigPublicKey, msg::Signer, verifier_set::VerifierSet};
use router_api::Message as RouterMessage;

use crate::{error::ContractError, payload::Payload};

sol!("src/encoding/abi/solidity/AmplifierGatewayTypes.sol");
sol!("src/encoding/abi/solidity/WeightedMultisigTypes.sol");

impl From<&Payload> for CommandType {
    fn from(payload: &Payload) -> Self {
        match payload {
            Payload::Messages(_) => CommandType::ApproveMessages,
            Payload::VerifierSet(_) => CommandType::RotateSigners,
        }
    }
}

impl WeightedSigners {
    pub fn hash(&self) -> Hash {
        Keccak256::digest(self.abi_encode()).into()
    }
}

impl From<&Signer> for WeightedSigner {
    fn from(signer: &Signer) -> Self {
        WeightedSigner {
            signer: evm_address(&signer.pub_key).expect("failed to convert pub key to evm address"),
            weight: signer.weight.u128(),
        }
    }
}

impl From<&VerifierSet> for WeightedSigners {
    fn from(verifier_set: &VerifierSet) -> Self {
        let mut signers = verifier_set
            .signers
            .values()
            .map(WeightedSigner::from)
            .collect::<Vec<_>>();

        signers.sort_by_key(|weighted_signer| weighted_signer.signer);

        WeightedSigners {
            signers,
            threshold: verifier_set.threshold.u128(),
            nonce: Uint256::from(verifier_set.created_at).to_be_bytes().into(),
        }
    }
}

impl TryFrom<&RouterMessage> for Message {
    type Error = ContractError;

    fn try_from(msg: &RouterMessage) -> Result<Self, Self::Error> {
        let contract_address =
            Address::from_str(msg.destination_address.as_str()).map_err(|err| {
                ContractError::InvalidMessage {
                    reason: format!("destination_address is not a valid EVM address: {}", err),
                }
            })?;

        let payload_hash = FixedBytes::<32>::from_slice(msg.payload_hash.as_slice());

        Ok(Message {
            sourceChain: msg.cc_id.chain.to_string(),
            messageId: msg.cc_id.id.to_string(),
            sourceAddress: msg.source_address.to_string(),
            contractAddress: contract_address,
            payloadHash: payload_hash,
        })
    }
}

pub fn payload_hash_to_sign(
    domain_separator: &Hash,
    signer: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    let signer_hash = WeightedSigners::from(signer).hash();
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
    let command_type = CommandType::from(payload);

    match payload {
        Payload::Messages(messages) => {
            let messages: Vec<_> = messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<_, _>>()?;

            Ok((command_type, messages).abi_encode_sequence())
        }
        Payload::VerifierSet(verifier_set) => {
            Ok((command_type, WeightedSigners::from(verifier_set)).abi_encode_sequence())
        }
    }
}

fn evm_address(pub_key: &MultisigPublicKey) -> Result<Address, ContractError> {
    match pub_key {
        MultisigPublicKey::Ecdsa(pub_key) => PublicKey::from_sec1_bytes(pub_key)
            .map(|pub_key| pub_key.to_encoded_point(false))
            .map(|pub_key| Address::from_raw_public_key(&pub_key.as_bytes()[1..]))
            .map_err(|err| ContractError::InvalidPublicKey {
                reason: err.to_string(),
            }),
        _ => Err(ContractError::InvalidPublicKey {
            reason: "expect ECDSA public key".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::HexBinary;

    use router_api::{CrossChainId, Message as RouterMessage};

    use crate::{
        encoding::abi::{payload_hash_to_sign, CommandType, Message, WeightedSigners},
        payload::Payload,
        test::test_data::{
            curr_verifier_set, domain_separator, messages, new_verifier_set,
            verifier_set_from_pub_keys,
        },
    };

    #[test]
    fn command_type_from_payload() {
        let payload = Payload::Messages(vec![]);
        assert_eq!(
            CommandType::from(&payload).as_u8(),
            CommandType::ApproveMessages.as_u8()
        );

        let payload = Payload::VerifierSet(new_verifier_set());
        assert_eq!(
            CommandType::from(&payload).as_u8(),
            CommandType::RotateSigners.as_u8()
        );
    }

    #[test]
    fn weight_signers_hash() {
        let expected_hash =
            HexBinary::from_hex("e490c7e55a46b0e1e39a3034973b676eed044fed387f80f4e6377305313f8762")
                .unwrap();
        let verifier_set = curr_verifier_set();

        assert_eq!(WeightedSigners::from(&verifier_set).hash(), expected_hash);
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
    fn router_message_to_gateway_message() {
        let source_chain = "chain0";
        let message_id = "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0";
        let source_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let destination_chain = "chain1";
        let destination_address = "0xA4f10f76B86E01B98daF66A3d02a65e14adb0767";
        let payload_hash = "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0";

        let router_messages = RouterMessage {
            cc_id: CrossChainId {
                chain: source_chain.parse().unwrap(),
                id: message_id.parse().unwrap(),
            },
            source_address: source_address.parse().unwrap(),
            destination_address: destination_address.parse().unwrap(),
            destination_chain: destination_chain.parse().unwrap(),
            payload_hash: HexBinary::from_hex(payload_hash)
                .unwrap()
                .to_array::<32>()
                .unwrap(),
        };

        let gateway_message = Message::try_from(&router_messages).unwrap();
        assert_eq!(gateway_message.sourceChain, source_chain);
        assert_eq!(gateway_message.messageId, message_id);
        assert_eq!(gateway_message.sourceAddress, source_address);
        assert_eq!(
            gateway_message.contractAddress.to_string(),
            destination_address
        );
        assert_eq!(
            gateway_message.payloadHash.to_string()[2..],
            payload_hash.to_string()
        );
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
