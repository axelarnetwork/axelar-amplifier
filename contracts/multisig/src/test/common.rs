use axelar_wasm_std::Participant;
use cosmwasm_std::{Addr, HexBinary, Uint256};

use crate::{
    key::{KeyType, PublicKey},
    worker_set::WorkerSet,
};

#[derive(Clone)]
pub struct TestSigner {
    pub address: Addr,
    pub pub_key: HexBinary,
    pub signature: HexBinary,
    pub signed_address: HexBinary,
}

pub mod ecdsa_test_data {
    use super::*;

    pub fn pub_key() -> HexBinary {
        HexBinary::from_hex("03a7e532333ba40803b7e5744cbc94e94e905c9ced87bbe08065e0cd36fa7e01c6")
            .unwrap()
    }

    pub fn signature() -> HexBinary {
        HexBinary::from_hex("2b777f1649d50dd86018d585fb12baca1c7f26e76c0b7b81c13ad198142186ad49b152cd3ccabe04c6ee841a3ecf0c3946ef8b922f50f858616fde89ac6e57b1")
            .unwrap()
    }

    pub fn message() -> HexBinary {
        HexBinary::from_hex("fa0609efd1dfeedfdcc8ba51520fae2d5176b7621d2560f071e801b0817e1537")
            .unwrap()
    }

    pub fn signers() -> Vec<TestSigner> {
        vec![
            TestSigner {
                address: Addr::unchecked("signer1"),
                pub_key: pub_key(),
                signature: signature(),
                signed_address: HexBinary::from_hex(
                    "b8b4c7e4423e80a71171d40709a1ca3b464b09ca93c4df9e13ef98df5d6d2d3b77a2fdf22a34b2946574801ee0d7fa886d8c3b34e63ca4158b74e02fe343ca47",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer2"),
                pub_key: pub_key(),
                signature: signature(),
                signed_address: HexBinary::from_hex(
                    "cca043f028c58d0c19d386535bfc69c5738927a8b8c097de178da65c997c48f5754deabeffd61f6c1632e4fda85c9cc2a14ae3aaa6fbb86ac3e55827d974b5be",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer3"),
                pub_key: pub_key(),
                signature: signature(),
                signed_address: HexBinary::from_hex(
                    "e7eac57ecf154ef96c92a3a67cfc9660086c3ad486fcb263e34f7f359819f7790e456bdaca0c7e6fe9be806310503819be287ae3bbed5fbbc2e7a184cc6cdf8d",
                )
                .unwrap(),
            },
        ]
    }
}

pub mod ed25519_test_data {
    use super::*;

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
        vec![
            TestSigner {
                address: Addr::unchecked("signer1"),
                pub_key: pub_key(),
                signature: signature(),
                signed_address: HexBinary::from_hex(
                    "7148e6050abb8aad613b3fc43e9db35ca665c96e4b78a8f3c319bc6fed084df9fc867c31bf3601cdd0315aab3542811ba45138f94e9f1902d06b2126e1b71801",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer2"),
                pub_key: pub_key(),
                signature: signature(),
                signed_address: HexBinary::from_hex(
                    "0c41f7e0bb078faf21d1170d5a6b26c770b41dc01069484d1848d5aaf7ba0a3a15d14fb10f8129e4f697b841fe496086ab8093f3a5cbdb688e3956366d0e9f08",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer3"),
                pub_key: pub_key(),
                signature: signature(),
                signed_address: HexBinary::from_hex(
                    "e07901993a6c0adca6ec87564805316e784fc77e65c099407111cec8d2095f84c3be4342ec3e3b630db0a21ff06ac31da57df8c78828b6675269a8186aacea04",
                )
                .unwrap(),
            },
        ]
    }
}

pub fn build_worker_set(key_type: KeyType, signers: &Vec<TestSigner>) -> WorkerSet {
    let mut total_weight = Uint256::zero();
    let participants = signers
        .iter()
        .map(|signer| {
            total_weight += Uint256::one();
            (
                Participant {
                    address: signer.address.clone(),
                    weight: Uint256::one().try_into().unwrap(),
                },
                PublicKey::try_from((key_type, signer.pub_key.clone())).unwrap(),
            )
        })
        .collect::<Vec<_>>();

    WorkerSet::new(participants, total_weight.mul_ceil((2u64, 3u64)), 0)
}
