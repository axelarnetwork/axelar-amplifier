use axelar_wasm_std::Participant;
use cosmwasm_std::{Addr, HexBinary, Uint128};

use crate::key::{KeyType, PublicKey};
use crate::verifier_set::VerifierSet;

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
        vec![
            TestSigner {
                address: Addr::unchecked("signer1"),
                pub_key: HexBinary::from_hex("025e0231bfad810e5276e2cf9eb2f3f380ce0bdf6d84c3b6173499d3ddcc008856")
            .unwrap(),
                signature: HexBinary::from_hex("d7822dd89b9df02d64b91f69cff5811dfd4de16b792d9c6054b417c733bbcc542c1e504c8a1dffac94b5828a93e33a6b45d1bf59b2f9f28ffa56b8398d68a1c5")
            .unwrap(),
                signed_address: HexBinary::from_hex(
                    "d9e1eb2b47cb8b7c1c2a5a32f6fa6c57d0e6fdd53eaa8c76fe7f0b3b390cfb3c40f258e476f2ca0e6a7ca2622ea23afe7bd1f873448e01eed86cd6446a403f36",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer2"),
                pub_key: HexBinary::from_hex("036ff6f4b2bc5e08aba924bd8fd986608f3685ca651a015b3d9d6a656de14769fe")
            .unwrap(),
                signature: HexBinary::from_hex("a7ec5d1c15e84ba4b5da23fee49d77c5c81b3b1859411d1ef8193bf5a39783c76813e4cf4e1e1bfa0ea19c9f5b61d25ce978da137f3adb1730cba3d842702e72")
            .unwrap(),
                signed_address: HexBinary::from_hex(
                    "008ca739eaddd22856c30690bf9a85f16ea77784494ad01111fded80327c57c84e021608cd890341883de1ac0fcf31330243b91b22c4751542ac47115f2f4e2c",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer3"),
                pub_key: HexBinary::from_hex("03686cbbef9f9e9a5c852883cb2637b55fc76bee6ee6a3ff636e7bea2e41beece4")
            .unwrap(),
                signature: HexBinary::from_hex("d1bc22fd89d97dfe4091c73d2002823ca9ab29b742ae531d2560bf2abafb313f7d2c3263d09d9aa72f01ed1d49046e39f6513ea61241fd59cc53d02fc4222351")
            .unwrap(),
                signed_address: HexBinary::from_hex(
                    "1df5a371c27772874b706dbbb41e0bc67f688b301d3c2d269e45c43389fa43b6328c32686f42242b0cdb05b3b955ce3106393d6e509bf0373340482182c865cc",
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
                pub_key: HexBinary::from_hex("45e67eaf446e6c26eb3a2b55b64339ecf3a4d1d03180bee20eb5afdd23fa644f")
            .unwrap(),
                signature: HexBinary::from_hex("bfbcd8e1f5ed0045d16738bab201ea843a2dc14af85887f0d3b17441988b356261095768578381ae5e096c08239f5d42ffd860ac706b464eb96d414abab2000c")
            .unwrap(),
                signed_address: HexBinary::from_hex(
                    "7148e6050abb8aad613b3fc43e9db35ca665c96e4b78a8f3c319bc6fed084df9fc867c31bf3601cdd0315aab3542811ba45138f94e9f1902d06b2126e1b71801",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer2"),
                pub_key: HexBinary::from_hex("dd9822c7fa239dda9913ebee813ecbe69e35d88ff651548d5cc42c033a8a667b")
            .unwrap(),
                signature: HexBinary::from_hex("9752f45bede164a4fc80d3f5641c853bd5ca79eb0c54405647adb62f5d19500978556b6a08f7e15506ca2691527ee2ebe95e06f961d18c6368c8a05736f8b301")
            .unwrap(),
                signed_address: HexBinary::from_hex(
                    "152fe2d807dce545e099b08b2cacf9c79f73167e6139e856b2baa64394c12ca74b87f650e3bdaf6e458e158eedb36af81872b880160ad238fdffeda614db3f01",
                )
                .unwrap(),
            },
            TestSigner {
                address: Addr::unchecked("signer3"),
                pub_key: HexBinary::from_hex("c387253d29085a8036d6ae2cafb1b14699751417c0ce302cfe03da279e6b5c04")
            .unwrap(),
                signature: HexBinary::from_hex("d6803f9c155a8f1c8863a08796825bf68f364db31e076187bcc29adfa846cbd5352052f196684decbf5aa12e23a6104acf671d249cc50a21e3a9d3fb7bffb307")
            .unwrap(),
                signed_address: HexBinary::from_hex(
                    "ea5462f8b7bc4f21e5e23873afb649158c0f57bd7a3872a677da952a468d72ebf742bc31e862d544ce19882aa8df66f1586ca1ab4af5069b6ac0c84e36dbae08",
                )
                .unwrap(),
            },
        ]
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
