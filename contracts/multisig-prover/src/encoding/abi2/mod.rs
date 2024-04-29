use alloy_primitives::Address;
use alloy_sol_types::{sol, SolValue};
use cosmwasm_std::{HexBinary, Uint128, Uint256};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use sha3::{Digest, Keccak256};

use axelar_wasm_std::hash::Hash;
use multisig::{key::PublicKey as MultisigPublicKey, msg::Signer, worker_set::WorkerSet};

use crate::error::ContractError;
use crate::types::Payload;

sol!("src/encoding/abi2/solidity/AmplifierGatewayTypes.sol");
sol!("src/encoding/abi2/solidity/WeightedMultisigTypes.sol");

impl From<&Payload> for CommandType {
    fn from(payload: &Payload) -> Self {
        match payload {
            Payload::Messages(_) => CommandType::ApproveMessages,
            Payload::WorkerSet(_) => CommandType::RotateSigners,
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
        let weight: Uint128 = signer
            .weight
            .try_into()
            .expect("weight is too large to convert to Uint128");

        WeightedSigner {
            signer: evm_address(&signer.pub_key).expect("failed to convert pub key to evm address"),
            weight: weight.u128(),
        }
    }
}

impl From<&WorkerSet> for WeightedSigners {
    fn from(worker_set: &WorkerSet) -> Self {
        let mut signers = worker_set
            .signers
            .values()
            .map(WeightedSigner::from)
            .collect::<Vec<_>>();

        signers.sort_by_key(|weighted_signer| weighted_signer.signer);

        let threshold: u128 = Uint128::try_from(worker_set.threshold)
            .expect("threshold is too large to convert to Uint128")
            .u128();

        WeightedSigners {
            signers,
            threshold,
            nonce: Uint256::from(worker_set.created_at).to_le_bytes().into(),
        }
    }
}

pub fn message_hash_to_sign(
    domain_separator: &Hash,
    signer: &WorkerSet,
    payload: &Payload,
) -> HexBinary {
    let signer = WeightedSigners::from(signer);
    let data_to_sign = encode(payload);

    // Prefix for standard EVM signed data https://eips.ethereum.org/EIPS/eip-191
    let unsigned = [
        "\x19Ethereum Signed Message:\n96".as_bytes(), // 96 is the length of the trailing bytes
        domain_separator,
        signer.hash().as_slice(),
        Keccak256::digest(data_to_sign.clone()).as_slice(),
    ]
    .concat();

    Keccak256::digest(unsigned).as_slice().into()
}

pub fn encode(payload: &Payload) -> Vec<u8> {
    match payload {
        Payload::Messages(_) => todo!(),
        Payload::WorkerSet(worker_set) => (
            CommandType::from(payload),
            WeightedSigners::from(worker_set),
        )
            .abi_encode_sequence(),
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
    use cosmwasm_std::{Addr, HexBinary, Uint256};

    use axelar_wasm_std::{nonempty, Participant};
    use multisig::{key::PublicKey, worker_set::WorkerSet};

    use crate::{
        encoding::abi2::{message_hash_to_sign, CommandType, WeightedSigners},
        test::test_data::new_worker_set,
        types::Payload,
    };

    #[test]
    fn command_type_from_payload() {
        let payload = Payload::Messages(vec![]);
        assert_eq!(
            CommandType::from(&payload).as_u8(),
            CommandType::ApproveMessages.as_u8()
        );

        let payload = Payload::WorkerSet(new_worker_set());
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
        let worker_set = curr_worker_set();

        assert_eq!(WeightedSigners::from(&worker_set).hash(), expected_hash);
    }

    #[test]
    fn rotate_signers_message_hash() {
        let expected_hash =
            HexBinary::from_hex("fbb9a154bbafd0be9469d7c83bfe5807d916ec7430f5232f29b967240880f327")
                .unwrap();

        let domain_separator: [u8; 32] =
            HexBinary::from_hex("3593643a7d7e917a099eef6c52d1420bb4f33eb074b16439556de5984791262b")
                .unwrap()
                .to_array()
                .unwrap();

        let new_pub_keys = vec![
            "02de8b0cc10de1becab121cb1254a7b4075866b6e040d5a4cdd38c7ea6c68c7d0a",
            "025a08780e7b80e64511006ec4db4128e18b31f05e9c8a4ef285322991d5f17332",
            "03935a5be97cf2148cb5cb88d5f097a235859a572f46e53da907e80fd5578f9243",
            "02515a95a89320988ff96f5e990b6d4c0a6807072f9b01c9ae634cf846bae2bd08",
            "02464111b31e5d174ec44c172f5e3913d0a35344ef6c2cd8215494f23648ec3420",
        ];
        let new_worker_set = worker_set_from_pub_keys(new_pub_keys);

        let msg_to_sign = message_hash_to_sign(
            &domain_separator,
            &curr_worker_set(),
            &Payload::WorkerSet(new_worker_set),
        );
        assert_eq!(msg_to_sign, expected_hash);
    }

    // generate a worker set matches AmplifierGateway solidity test data
    fn curr_worker_set() -> WorkerSet {
        let pub_keys = vec![
            "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0",
            "039d9031e97dd78ff8c15aa86939de9b1e791066a0224e331bc962a2099a7b1f04",
            "0220b871f3ced029e14472ec4ebc3c0448164942b123aa6af91a3386c1c403e0eb",
            "03bf6ee64a8d2fdc551ec8bb9ef862ef6b4bcb1805cdc520c3aa5866c0575fd3b5",
        ];

        worker_set_from_pub_keys(pub_keys)
    }

    fn worker_set_from_pub_keys(pub_keys: Vec<&str>) -> WorkerSet {
        let participants: Vec<(_, _)> = (0..pub_keys.len())
            .map(|i| {
                (
                    Participant {
                        address: Addr::unchecked(format!("verifier{i}")),
                        weight: nonempty::Uint256::one(),
                    },
                    PublicKey::Ecdsa(HexBinary::from_hex(pub_keys[i]).unwrap()),
                )
            })
            .collect();
        WorkerSet::new(participants, Uint256::from_u128(3), 0)
    }
}
