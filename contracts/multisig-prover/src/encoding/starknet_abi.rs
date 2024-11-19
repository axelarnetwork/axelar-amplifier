use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use error_stack::{Result, ResultExt};
use ethers_core::abi::{encode as abi_encode, Token, Tokenizable, Tokenize};
use evm_gateway::{CommandType, Proof, RotateSignersCall, WeightedSigners};
use itertools::Itertools;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use sha3::{Digest, Keccak256};
use starknet_types::types::starknet_message::StarknetMessage;

use crate::error::ContractError;
use crate::payload::Payload;

// NOTE: The functionality here is almost exactly the same as the ethereum abi implementation
// The main differences are that:
// - the "Ethereum Signer Message" prefix is gone
// - `RouterMessage` is converted to a `StarknetMessage` type, instead of the
//   ABI generated `Message` type. The reason is that the contract address
//   needs to be a valid `FieldElement` and ABI encoded to bytes32, instead of
//   address, and the `payload_hash` is of type U256.
// - ABI encoded function selectors are removed
//
// `Proof`, `WeightedSigners` and `CommandType` types are still used and generated
// from the ABI file, just like in ethereum.
// The resulting ABI encoding bytes, for execute_data and payload, are the same
// as in ethereum (without the function selector bytes in the beginning).

const PREFIX: &str = "\x19Ethereum Signed Message:\n96";

pub fn payload_digest(
    domain_separator: &Hash,
    signer: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    let signer_hash = WeightedSigners::try_from(signer)
        .map(|signers| signers.hash())
        .change_context(ContractError::InvalidVerifierSet)?;

    let data_hash = Keccak256::digest(encode_payload(payload)?);

    // Prefix for standard EVM signed data https://eips.ethereum.org/EIPS/eip-191
    let unsigned = [
        PREFIX.as_bytes(),
        domain_separator,
        signer_hash.as_slice(),
        data_hash.as_slice(),
    ]
    .concat();

    Ok(Keccak256::digest(unsigned).into())
}

pub fn encode_payload(payload: &Payload) -> Result<Vec<u8>, ContractError> {
    let command_type = CommandType::from(payload).into();

    match payload {
        Payload::Messages(messages) => {
            let messages = messages
                .iter()
                .map(StarknetMessage::try_from)
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

pub fn encode_execute_data(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    signers: Vec<SignerWithSig>,
    payload: &Payload,
) -> error_stack::Result<HexBinary, ContractError> {
    let signers = super::abi::to_recoverable(
        payload_digest(domain_separator, verifier_set, payload)?,
        signers,
    );

    let proof = Proof::new(verifier_set, signers).change_context(ContractError::Proof)?;

    let encoded = match payload {
        Payload::Messages(messages) => {
            let messages = messages
                .iter()
                .map(StarknetMessage::try_from)
                .map_ok(|m| Token::Tuple(m.into_tokens()))
                .collect::<Result<Vec<_>, _>>()
                .change_context(ContractError::InvalidMessage)?;

            abi_encode(&[Token::Array(messages), proof.into_token()])
        }
        Payload::VerifierSet(new_verifier_set) => {
            let new_signers = WeightedSigners::try_from(new_verifier_set)
                .change_context(ContractError::InvalidVerifierSet)?;

            abi_encode(&RotateSignersCall { new_signers, proof }.into_tokens())
        }
    };

    Ok(encoded.into())
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use cosmwasm_std::HexBinary;

    use crate::encoding::abi::tests::signers_with_sigs;
    use crate::encoding::starknet_abi::{encode_execute_data, payload_digest};
    use crate::payload::Payload;
    use crate::test::test_data::{
        curr_verifier_set, domain_separator, messages, verifier_set_from_pub_keys,
    };

    #[test]
    fn starknet_abi_verifier_set_payload_digest() {
        let domain_separator = domain_separator();

        let new_pub_keys = vec![
            "02de8b0cc10de1becab121cb1254a7b4075866b6e040d5a4cdd38c7ea6c68c7d0a",
            "025a08780e7b80e64511006ec4db4128e18b31f05e9c8a4ef285322991d5f17332",
            "03935a5be97cf2148cb5cb88d5f097a235859a572f46e53da907e80fd5578f9243",
            "02515a95a89320988ff96f5e990b6d4c0a6807072f9b01c9ae634cf846bae2bd08",
            "02464111b31e5d174ec44c172f5e3913d0a35344ef6c2cd8215494f23648ec3420",
        ];

        let mut new_verifier_set = verifier_set_from_pub_keys(new_pub_keys);
        new_verifier_set.created_at = 2024;

        let payload_digest = assert_ok!(payload_digest(
            &domain_separator,
            &curr_verifier_set(),
            &Payload::VerifierSet(new_verifier_set),
        ));

        goldie::assert!(hex::encode(payload_digest));
    }

    #[test]
    fn starknet_abi_approve_messages_payload_digest() {
        let domain_separator = domain_separator();
        let payload_digest = assert_ok!(payload_digest(
            &domain_separator,
            &curr_verifier_set(),
            &Payload::Messages(messages()),
        ));

        goldie::assert!(hex::encode(payload_digest));
    }

    #[test]
    fn starknet_abi_rotate_signers_execute_data() {
        let domain_separator = domain_separator();

        let new_pub_keys = vec![
            "0352a321079b435a4566ac8c92ab18584d8537d563f6c2c0bbbf58246ad047c611",
            "03b80cd1fff796fb80a82f4d45b812451668791a85a58c8c0b5939d75f126f80b1",
            "0251f7035a693e804eaed139009ede4ef62215914ccf9080027d53ef6bbb8897c5",
            "03a907596748daa5ae9c522445529ca38d0ea2c47a908c30643ca37a0e6e12160d",
            "03c55d66787c66f37257ef4b320ddcb64623d59e9bf0f3ec0f8ac7311b70cdd2c8",
        ];

        let mut new_verifier_set = verifier_set_from_pub_keys(new_pub_keys);
        new_verifier_set.created_at = 2024;

        let verifier_set = curr_verifier_set();

        // Generated signatures are already sorted by weight and evm address
        let sigs: Vec<_> = vec![
            "e3a7c09bfa26df8bbd207df89d7ba01100b809324b2987e1426081284a50485345a5a20b6d1d5844470513099937f1015ce8f4832d3df97d053f044103434d8c1b",
            "895dacfb63684da2360394d5127696129bd0da531d6877348ff840fb328297f870773df3c259d15dd28dbd51d87b910e4156ff2f3c1dc5f64d337dea7968a9401b",
            "7c685ecc8a42da4cd9d6de7860b0fddebb4e2e934357500257c1070b1a15be5e27f13b627cf9fa44f59d535af96be0a5ec214d988c48e2b5aaf3ba537d0215bb1b",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let payload = Payload::VerifierSet(new_verifier_set);

        let execute_data = assert_ok!(encode_execute_data(
            &domain_separator,
            &verifier_set,
            signers_with_sigs,
            &payload
        ));

        // Note: goldie doesn't work without the abi function selector bytes for some reason.
        // The string here just has the 4 function selector bytes removed.
        assert_eq!(execute_data.to_hex(), "000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000007e80000000000000000000000000000000000000000000000000000000000000005000000000000000000000000126d4f2f15c471053968bdc5d53fe247499e2909000000000000000000000000000000000000000000000000000000000000000100000000000000000000000032ef31fbaea000336992ba75bd17ef632c3f55750000000000000000000000000000000000000000000000000000000000000001000000000000000000000000597d565dfe207dd6bc93ea291cbcc029b00c605a00000000000000000000000000000000000000000000000000000000000000010000000000000000000000007c53e31d6622e6dc761a029b5a1295afc98cda710000000000000000000000000000000000000000000000000000000000000001000000000000000000000000ef02cff50b393f6b233d4c50e88346af920825a4000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000500000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a6500000000000000000000000000000000000000000000000000000000000000010000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000100000000000000000000000090f79bf6eb2c4f870365e785982e1f101e93b9060000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041e3a7c09bfa26df8bbd207df89d7ba01100b809324b2987e1426081284a50485345a5a20b6d1d5844470513099937f1015ce8f4832d3df97d053f044103434d8c1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041895dacfb63684da2360394d5127696129bd0da531d6877348ff840fb328297f870773df3c259d15dd28dbd51d87b910e4156ff2f3c1dc5f64d337dea7968a9401b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000417c685ecc8a42da4cd9d6de7860b0fddebb4e2e934357500257c1070b1a15be5e27f13b627cf9fa44f59d535af96be0a5ec214d988c48e2b5aaf3ba537d0215bb1b00000000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn starknet_abi_approve_messages_execute_data() {
        let domain_separator = domain_separator();
        let verifier_set = curr_verifier_set();

        // Generated signatures are already sorted by weight and evm address
        let sigs: Vec<_> = vec![
            "756473c3061df7ea3fef7c52e0e875dca2c93f08ce4f1d33e694d64c713a56842017d92f0a1b796afe1c5343677ff261a072fb210ff3d43cc2784c0774d4da7b1b",
            "5bdad2b95e700283402392a2f5878d185f92d588a6b4868460977c4f06f4216f0452c2e215c2878fe6e146db5b74f278716a99b418c6b2cb1d812ad28e686cd81c",
            "4c9c52a99a3941a384c4a80b3c5a14c059020d3d2f29be210717bdb9270ed55937fcec824313c90c198188ea8eb3b47c2bafe5e96c11f79ec793d589358024191b",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let payload = Payload::Messages(messages());
        let execute_data = assert_ok!(encode_execute_data(
            &domain_separator,
            &verifier_set,
            signers_with_sigs,
            &payload
        ));

        // Note: goldie doesn't work without the abi function selector bytes for some reason.
        // The string here just has the 4 function selector bytes removed.
        assert_eq!(execute_data.to_hex(), "000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000a4f10f76b86e01b98daf66a3d02a65e14adb07678c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0000000000000000000000000000000000000000000000000000000000000000967616e616368652d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000443078666638323263383838303738353966663232366235386532346632343937346137306630346239343432353031616533386664363635623363363866333833342d3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a3078353234343466313833354164633032303836633337436232323635363136303565324531363939620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000500000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a6500000000000000000000000000000000000000000000000000000000000000010000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000100000000000000000000000090f79bf6eb2c4f870365e785982e1f101e93b9060000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041756473c3061df7ea3fef7c52e0e875dca2c93f08ce4f1d33e694d64c713a56842017d92f0a1b796afe1c5343677ff261a072fb210ff3d43cc2784c0774d4da7b1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000415bdad2b95e700283402392a2f5878d185f92d588a6b4868460977c4f06f4216f0452c2e215c2878fe6e146db5b74f278716a99b418c6b2cb1d812ad28e686cd81c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000414c9c52a99a3941a384c4a80b3c5a14c059020d3d2f29be210717bdb9270ed55937fcec824313c90c198188ea8eb3b47c2bafe5e96c11f79ec793d589358024191b00000000000000000000000000000000000000000000000000000000000000");
    }
}
