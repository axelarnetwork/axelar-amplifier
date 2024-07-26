use std::str::FromStr;

use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::FnExt;
use cosmwasm_std::Uint256;
use error_stack::{Report, ResultExt};
use ethers_contract::abigen;
use ethers_core::abi::Token::{self, Tuple, Uint};
use ethers_core::abi::{encode, Tokenize};
use ethers_core::types::{Address, Bytes, U256};
use ethers_core::utils::public_key_to_address;
use k256::ecdsa::VerifyingKey;
use multisig::key::PublicKey;
use multisig::msg::{Signer, SignerWithSig};
use multisig::verifier_set::VerifierSet;
use router_api::Message as RouterMessage;
use sha3::{Digest, Keccak256};

use crate::error::Error;

pub mod error;

// Generates the bindings for the Axelar Amplifier Gateway contract.
// This includes the defined structs: Messages, WeightedSigners, WeightedSigner, and Proofs.
abigen!(
    IAxelarAmplifierGateway,
    "src/abi/IAxelarAmplifierGateway.json"
);

impl TryFrom<&VerifierSet> for WeightedSigners {
    type Error = Report<Error>;

    fn try_from(verifier_set: &VerifierSet) -> Result<Self, Self::Error> {
        let mut signers: Vec<_> = verifier_set
            .signers
            .values()
            .map(WeightedSigner::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        signers.sort_by_key(|weighted_signer| weighted_signer.signer);

        Ok(WeightedSigners {
            signers,
            threshold: verifier_set.threshold.u128(),
            nonce: Uint256::from(verifier_set.created_at).to_be_bytes(),
        })
    }
}

impl TryFrom<&Signer> for WeightedSigner {
    type Error = Report<Error>;

    fn try_from(signer: &Signer) -> Result<Self, Self::Error> {
        Ok(WeightedSigner {
            signer: evm_address(&signer.pub_key)?,
            weight: signer.weight.u128(),
        })
    }
}

impl WeightedSigners {
    pub fn abi_encode(&self) -> Vec<u8> {
        let tokens = self.clone().into_tokens();

        encode(&[Tuple(tokens)])
    }

    pub fn hash(&self) -> Hash {
        Keccak256::digest(self.abi_encode()).into()
    }
}

impl TryFrom<&RouterMessage> for Message {
    type Error = Report<Error>;

    fn try_from(msg: &RouterMessage) -> Result<Self, Self::Error> {
        let contract_address = msg
            .destination_address
            .as_str()
            .then(|addr| addr.strip_prefix("0x").unwrap_or(addr))
            .then(Address::from_str)
            .change_context(Error::InvalidAddress)?;

        Ok(Message {
            source_chain: msg.cc_id.source_chain.to_string(),
            message_id: msg.cc_id.message_id.to_string(),
            source_address: msg.source_address.to_string(),
            contract_address,
            payload_hash: msg.payload_hash,
        })
    }
}

impl Proof {
    /// Proof contains the entire verifier set and optimized signatures. Signatures are sorted in ascending order based on the signer's address.
    pub fn new(
        verifier_set: &VerifierSet,
        mut signers_with_sigs: Vec<SignerWithSig>,
    ) -> Result<Self, Report<Error>> {
        let signers = WeightedSigners::try_from(verifier_set)?;

        // The conversion from the public key to the EVM address must be successful,
        // otherwise WeightedSigners::try_from would have returned an error.
        signers_with_sigs.sort_by_key(|signer| {
            evm_address(&signer.signer.pub_key).expect("failed to convert pub key to evm address")
        });

        let signatures = signers_with_sigs
            .into_iter()
            .map(|signer| Bytes::from(signer.signature.as_ref().to_vec()))
            .collect::<Vec<_>>();

        Ok(Proof {
            signers,
            signatures,
        })
    }
}

#[derive(PartialEq, Debug)]
pub enum CommandType {
    ApproveMessages,
    RotateSigners,
}

impl From<CommandType> for Token {
    fn from(command_type: CommandType) -> Self {
        match command_type {
            CommandType::ApproveMessages => Uint(U256::zero()),
            CommandType::RotateSigners => Uint(U256::one()),
        }
    }
}

pub fn evm_address(pub_key: &PublicKey) -> Result<Address, Report<Error>> {
    match pub_key {
        PublicKey::Ecdsa(pub_key) => VerifyingKey::from_sec1_bytes(pub_key)
            .map(|v| public_key_to_address(&v))
            .change_context(Error::InvalidPublicKey),
        _ => Err(Error::InvalidPublicKey).attach_printable("expect ECDSA public key"),
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axelar_wasm_std::nonempty;
    use axelar_wasm_std::snapshot::Participant;
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use multisig::key::PublicKey;
    use multisig::verifier_set::VerifierSet;
    use router_api::{CrossChainId, Message as RouterMessage};

    use crate::{Message, WeightedSigners};

    #[test]
    fn weight_signers_hash() {
        let expected_hash =
            HexBinary::from_hex("e490c7e55a46b0e1e39a3034973b676eed044fed387f80f4e6377305313f8762")
                .unwrap();
        let verifier_set = curr_verifier_set();

        assert_eq!(
            WeightedSigners::try_from(&verifier_set).unwrap().hash(),
            expected_hash
        );
    }

    #[test]
    fn router_message_to_gateway_message() {
        let source_chain = "chain0";
        let message_id = "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0";
        let source_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let destination_chain = "chain1";
        let payload_hash = "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0";
        let destination_addresses = vec![
            "0xa4f10f76b86e01b98daf66a3d02a65e14adb0767", // all lowercase
            "0xA4f10f76B86E01B98daF66A3d02a65e14adb0767", // checksummed
            "a4f10f76b86e01b98daf66a3d02a65e14adb0767",   // no 0x prefix
        ];

        for destination_address in destination_addresses {
            let router_messages = RouterMessage {
                cc_id: CrossChainId::new(source_chain, message_id).unwrap(),
                source_address: source_address.parse().unwrap(),
                destination_address: destination_address.parse().unwrap(),
                destination_chain: destination_chain.parse().unwrap(),
                payload_hash: HexBinary::from_hex(payload_hash)
                    .unwrap()
                    .to_array::<32>()
                    .unwrap(),
            };

            let gateway_message = Message::try_from(&router_messages).unwrap();
            assert_eq!(gateway_message.source_chain, source_chain);
            assert_eq!(gateway_message.message_id, message_id);
            assert_eq!(gateway_message.source_address, source_address);
            assert_eq!(
                gateway_message.contract_address,
                ethers_core::types::Address::from_str(
                    destination_address
                        .strip_prefix("0x")
                        .unwrap_or(destination_address)
                )
                .unwrap()
            );
            assert_eq!(gateway_message.payload_hash, router_messages.payload_hash);
        }
    }

    // Generate a worker set matches axelar-gmp-sdk-solidity repo test data
    pub fn curr_verifier_set() -> VerifierSet {
        let pub_keys = vec![
            "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0",
            "039d9031e97dd78ff8c15aa86939de9b1e791066a0224e331bc962a2099a7b1f04",
            "0220b871f3ced029e14472ec4ebc3c0448164942b123aa6af91a3386c1c403e0eb",
            "03bf6ee64a8d2fdc551ec8bb9ef862ef6b4bcb1805cdc520c3aa5866c0575fd3b5",
        ];

        verifier_set_from_pub_keys(pub_keys)
    }

    pub fn verifier_set_from_pub_keys(pub_keys: Vec<&str>) -> VerifierSet {
        let participants: Vec<(_, _)> = (0..pub_keys.len())
            .map(|i| {
                (
                    Participant {
                        address: Addr::unchecked(format!("verifier{i}")),
                        weight: nonempty::Uint128::one(),
                    },
                    PublicKey::Ecdsa(HexBinary::from_hex(pub_keys[i]).unwrap()),
                )
            })
            .collect();
        VerifierSet::new(participants, Uint128::from(3u128), 0)
    }
}
