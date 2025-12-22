use std::collections::BTreeMap;

use axelar_wasm_std::{nonempty, Participant};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::testing::MockApi;
use cosmwasm_std::{Addr, HexBinary, Uint128};
use multisig::key::Signature;
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use router_api::{CrossChainId, Message};

pub fn new_verifier_set() -> VerifierSet {
    let signers = vec![
        Signer {
            address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
            weight: Uint128::from(10u128),
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
                )
                .unwrap(),
            ),
        },
        Signer {
            address: Addr::unchecked("axelarvaloper1ff675m593vve8yh82lzhdnqfpu7m23cxstr6h4"),
            weight: Uint128::from(10u128),
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03c6ddb0fcee7b528da1ef3c9eed8d51eeacd7cc28a8baa25c33037c5562faa6e4",
                )
                .unwrap(),
            ),
        },
        Signer {
            address: Addr::unchecked("axelarvaloper12cwre2gdhyytc3p97z9autzg27hmu4gfzz4rxc"),
            weight: Uint128::from(10u128),
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "0274b5d2a4c55d7edbbf9cc210c4d25adbb6194d6b444816235c82984bee518255",
                )
                .unwrap(),
            ),
        },
        Signer {
            address: Addr::unchecked("axelarvaloper1vs9rdplntrf7ceqdkznjmanrr59qcpjq6le0yw"),
            weight: Uint128::from(10u128),
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "02a670f57de55b8b39b4cb051e178ca8fb3fe3a78cdde7f8238baf5e6ce1893185",
                )
                .unwrap(),
            ),
        },
        Signer {
            address: Addr::unchecked("axelarvaloper1hz0slkejw96dukw87fztjkvwjdpcu20jewg6mw"),
            weight: Uint128::from(10u128),
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "028584592624e742ba154c02df4c0b06e4e8a957ba081083ea9fe5309492aa6c7b",
                )
                .unwrap(),
            ),
        },
    ];

    let mut btree_signers = BTreeMap::new();
    for signer in signers {
        btree_signers.insert(signer.address.clone().to_string(), signer);
    }

    VerifierSet {
        signers: btree_signers,
        threshold: Uint128::from(30u128),
        created_at: 1,
    }
}

pub fn messages() -> Vec<Message> {
    vec![Message {
        cc_id: CrossChainId::new(
            "ganache-1",
            "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
        )
        .unwrap(),
        source_address: "0x52444f1835Adc02086c37Cb226561605e2E1699b"
            .parse()
            .unwrap(),
        destination_address: "0xA4f10f76B86E01B98daF66A3d02a65e14adb0767"
            .parse()
            .unwrap(),
        destination_chain: "ganache-0".parse().unwrap(),
        payload_hash: HexBinary::from_hex(
            "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0",
        )
        .unwrap()
        .to_array::<32>()
        .unwrap(),
    }]
}

#[cw_serde]
pub struct TestOperator {
    pub address: Addr,
    pub pub_key: multisig::key::PublicKey,
    pub operator: HexBinary,
    pub weight: Uint128,
    pub signature: Option<Signature>,
}

// Generate a verifier set matches axelar-gmp-sdk-solidity repo test data
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
                    address: MockApi::default().addr_make(format!("verifier{i}").as_str()),
                    weight: nonempty::Uint128::one(),
                },
                multisig::key::PublicKey::Ecdsa(HexBinary::from_hex(pub_keys[i]).unwrap()),
            )
        })
        .collect();
    VerifierSet::new(participants, Uint128::from(3u128), 1)
}

// Domain separator matches axelar-gmp-sdk-solidity repo test data
pub fn domain_separator() -> [u8; 32] {
    HexBinary::from_hex("3593643a7d7e917a099eef6c52d1420bb4f33eb074b16439556de5984791262b")
        .unwrap()
        .to_array()
        .unwrap()
}
