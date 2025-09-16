use axelar_wasm_std::Participant;
use cosmwasm_std::{Addr, HexBinary, Uint128, Uint64};
use k256::ecdsa::signature::hazmat::PrehashSigner;

use crate::key::{KeyType, PublicKey};
use crate::verifier_set::VerifierSet;

#[derive(Clone, Debug)]
pub struct TestSigner {
    pub address: Addr,
    pub pub_key: HexBinary,
    pub signature: HexBinary,
    pub signed_address: HexBinary,
}

pub mod ecdsa_test_data {
    use k256::ecdsa::{Signature, SigningKey};
    use router_api::cosmos_addr;
    use sha3::{Digest, Keccak256};

    use super::*;

    pub fn new(address: Addr, signing_key: SigningKey) -> TestSigner {
        let address_hash = Keccak256::digest(address.as_bytes());
        let verifying_key = signing_key.verifying_key();
        let signature: Signature = signing_key.sign_prehash(message().as_slice()).unwrap();
        let signed_address: Signature = signing_key.sign_prehash(address_hash.as_slice()).unwrap();

        TestSigner {
            address,
            pub_key: verifying_key.to_sec1_bytes().to_vec().into(),
            signature: signature.to_bytes().to_vec().into(),
            signed_address: signed_address.to_bytes().to_vec().into(),
        }
    }

    pub fn pub_key() -> HexBinary {
        HexBinary::from_hex("025e0231bfad810e5276e2cf9eb2f3f380ce0bdf6d84c3b6173499d3ddcc008856")
            .unwrap()
    }

    pub fn signature() -> HexBinary {
        HexBinary::from_hex("d7822dd89b9df02d64b91f69cff5811dfd4de16b792d9c6054b417c733bbcc542c1e504c8a1dffac94b5828a93e33a6b45d1bf59b2f9f28ffa56b8398d68a1c5")
            .unwrap()
    }

    pub fn message() -> HexBinary {
        HexBinary::from_hex("fa0609efd1dfeedfdcc8ba51520fae2d5176b7621d2560f071e801b0817e1537")
            .unwrap()
    }

    pub fn signers() -> Vec<TestSigner> {
        let addresses = vec![
            cosmos_addr!("signer1"),
            cosmos_addr!("signer2"),
            cosmos_addr!("signer3"),
        ]
        .into_iter();
        let signing_keys = vec![
            "0002735b006b54c6f73c23f3bb0331ce930baed3afe7a56629129efc54652101",
            "1f33707db21df35e138c071766c0bbdd5430869980f97ec9a90afbf0d8700d11",
            "1064549e232c591f916533b36df33e6ab9a491103912ace1e3b8b9d51b155666",
        ]
        .into_iter()
        .map(|hex| {
            k256::ecdsa::SigningKey::from_slice(HexBinary::from_hex(hex).unwrap().as_slice())
                .unwrap()
        });

        addresses
            .zip(signing_keys)
            .map(|(address, signing_key)| new(address, signing_key))
            .collect()
    }
}

pub mod ed25519_test_data {
    use k256::ecdsa::signature::SignerMut;
    use router_api::cosmos_addr;
    use sha3::{Digest, Keccak256};

    use super::*;

    pub fn new(address: Addr, mut signing_key: ed25519_dalek::SigningKey) -> TestSigner {
        let address_hash = Keccak256::digest(address.as_bytes());
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(message().as_slice());
        let signed_address = signing_key.sign(address_hash.as_slice());

        TestSigner {
            address,
            pub_key: verifying_key.to_bytes().to_vec().into(),
            signature: signature.to_bytes().to_vec().into(),
            signed_address: signed_address.to_bytes().to_vec().into(),
        }
    }

    pub fn pub_key() -> HexBinary {
        HexBinary::from_hex("45e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f")
            .unwrap()
    }

    pub fn signature() -> HexBinary {
        HexBinary::from_hex("bfbcd8e1f5ed0045d16738bab201ea843a2dc14af85887f0d3b17441988b356261095768578381ae5e096c08239f5d42ffd860ac706b464eb96d414abab2000c")
            .unwrap()
    }

    pub fn message() -> HexBinary {
        HexBinary::from_hex("fa0609efd1dfeedfdcc8ba51520fae2d5176b7621d2560f071e801b0817e1537")
            .unwrap()
    }

    pub fn signers() -> Vec<TestSigner> {
        let addresses = vec![
            cosmos_addr!("signer1"),
            cosmos_addr!("signer2"),
            cosmos_addr!("signer3"),
        ]
        .into_iter();
        let signing_keys = vec![
            "0002735b006b54c6f73c23f3bb0331ce930baed3afe7a56629129efc54652101",
            "1f33707db21df35e138c071766c0bbdd5430869980f97ec9a90afbf0d8700d11",
            "1064549e232c591f916533b36df33e6ab9a491103912ace1e3b8b9d51b155666",
        ]
        .into_iter()
        .map(|hex| {
            ed25519_dalek::SigningKey::try_from(HexBinary::from_hex(hex).unwrap().as_slice())
                .unwrap()
        });

        addresses
            .zip(signing_keys)
            .map(|(address, signing_key)| new(address, signing_key))
            .collect()
    }
}

pub mod aleo_schnorr_test_data {
    // APrivateKey1zkpEjXSofaQtApqm33wYLmHiGNLb99VZqLeRW19xWKHQWZW
    // AViewKey1gmHkeDm2NEvJSWUTRf9SCwaEU6uSjdYnaSXa7dsn67QW
    // aleo1et20lkz4f4a849mmnpz4670gpaekp030prm69eymaep8jppglsyslhyf9n

    use std::str::FromStr;

    use cosmwasm_std::testing::MockApi;
    use rand_chacha::rand_core::SeedableRng;
    use snarkvm_cosmwasm::console::account::PrivateKey;
    use snarkvm_cosmwasm::prelude::{FromBytes as _, Group, ToBytes as _, ToFields as _};

    use super::*;

    pub fn new(
        address: Addr,
        private_key: PrivateKey<snarkvm_cosmwasm::console::network::TestnetV0>,
    ) -> TestSigner {
        let verifying_key =
            snarkvm_cosmwasm::console::account::Address::try_from(&private_key).unwrap();
        let group_hash =
            Group::<snarkvm_cosmwasm::console::network::TestnetV0>::from_bytes_le(&message())
                .unwrap();

        let signature = snarkvm_cosmwasm::console::account::signature::Signature::sign(
            &private_key,
            &group_hash.to_fields().unwrap(),
            &mut rand_chacha::ChaChaRng::from_seed([1u8; 32]),
        )
        .unwrap();

        TestSigner {
            address,
            pub_key: verifying_key.to_bytes_le().unwrap().into(),
            signature: signature.to_bytes_le().unwrap().into(),
            signed_address: HexBinary::default(),
        }
    }

    pub fn pub_key() -> HexBinary {
        HexBinary::from(
            "aleo1et20lkz4f4a849mmnpz4670gpaekp030prm69eymaep8jppglsyslhyf9n".as_bytes(),
        )
    }

    pub fn signature() -> HexBinary {
        HexBinary::from("sign156wgsta9htrmyav5a6lrex6qu0eherjgvthkheelv3gkdxgtksq2ndv3547e7gq0xnwallk5tc407cyxkexnhvv3qqtfmyhqs095sqg5hht9cgrfl42000szdz9kg0wkvut6ff5czfgj6ctr7j7k7dxlqyz483xpxr5c70wjwh6a233d2puds04vfy9plrgzsz2vpqlypc0qqca3azj".as_bytes())
    }

    pub fn message() -> HexBinary {
        let group_value =
            Group::<snarkvm_cosmwasm::console::network::TestnetV0>::from_str("2group").unwrap();
        let bytes = group_value.to_bytes_le().unwrap();
        HexBinary::from(bytes)
    }

    pub fn signers() -> Vec<TestSigner> {
        let api = MockApi::default();
        let addresses = vec!["signer1", "signer2", "signer3"]
            .into_iter()
            .map(|name| api.addr_make(name));
        let signing_keys = vec![
            "APrivateKey1zkpEjXSofaQtApqm33wYLmHiGNLb99VZqLeRW19xWKHQWZW",
            "APrivateKey1zkp84oDcibJzwhyf2qNKCV6niZKg1ti619fbLZwUpnSW181",
            "APrivateKey1zkp6tvsgBKfPfsZVG5mBxU8sVMk8y7vxBjn6DFW5bogvVmg",
        ]
        .into_iter()
        .map(|key| PrivateKey::from_str(key).unwrap());

        addresses
            .zip(signing_keys)
            .map(|(address, signing_key)| new(address, signing_key))
            .collect()
    }
}

#[allow(clippy::arithmetic_side_effects)]
pub fn build_verifier_set(key_type: KeyType, signers: &[TestSigner]) -> VerifierSet {
    let mut total_weight = Uint128::zero();
    let participants = signers
        .iter()
        .map(|signer| {
            total_weight += Uint128::one();
            (
                Participant {
                    address: signer.address.clone(),
                    weight: Uint128::one().try_into().unwrap(),
                },
                PublicKey::try_from((key_type, signer.pub_key.clone())).unwrap(),
            )
        })
        .collect::<Vec<_>>();

    VerifierSet::new(participants, total_weight.mul_ceil((2u64, 3u64)), 0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifierSetId {
    Ecdsa(String),
    Ed25519(String),
    AleoSchnorr(String),
}

impl VerifierSetId {
    pub fn id(&self) -> &str {
        match self {
            VerifierSetId::Ecdsa(id) => id,
            VerifierSetId::Ed25519(id) => id,
            VerifierSetId::AleoSchnorr(id) => id,
        }
    }
}

// Returns a list of (key_type, subkey, signers, session_id)
pub fn signature_test_data<'a>(
    ecdsa_subkey: &'a VerifierSetId,
    ed25519_subkey: &'a VerifierSetId,
    aleo_schnorr_subkey: &'a VerifierSetId,
) -> Vec<(KeyType, &'a VerifierSetId, Vec<TestSigner>, Uint64)> {
    vec![
        (
            KeyType::Ecdsa,
            ecdsa_subkey,
            ecdsa_test_data::signers(),
            Uint64::from(1u64),
        ),
        (
            KeyType::Ed25519,
            ed25519_subkey,
            ed25519_test_data::signers(),
            Uint64::from(2u64),
        ),
        (
            KeyType::AleoSchnorr,
            aleo_schnorr_subkey,
            aleo_schnorr_test_data::signers(),
            Uint64::from(3u64),
        ),
    ]
}
