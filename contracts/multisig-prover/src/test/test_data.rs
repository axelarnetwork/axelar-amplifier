use std::collections::BTreeMap;

use axelar_wasm_std::{nonempty, MajorityThreshold, Participant, Threshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint128, Uint64};
use multisig::key::{KeyType, Signature};
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

pub fn approve_messages_calldata() -> HexBinary {
    HexBinary::from_hex("64f1d85a000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000a4f10f76b86e01b98daf66a3d02a65e14adb07678c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0000000000000000000000000000000000000000000000000000000000000000967616e616368652d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000443078666638323263383838303738353966663232366235386532346632343937346137306630346239343432353031616533386664363635623363363866333833342d3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a307835323434346631383335416463303230383663333743623232363536313630356532453136393962000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000050000000000000000000000004ef5c8d81b6417fa80c320b5fc1d3900506dff5400000000000000000000000000000000000000000000000000000000000000010000000000000000000000006c51eec96bf0a8ec799cdd0bbcb4512f8334afe800000000000000000000000000000000000000000000000000000000000000010000000000000000000000007aeb4eebf1e8dcde3016d4e1dca52b4538cf7aaf0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c5b95c99d883c3204cfc2e73669ce3aa7437f4a60000000000000000000000000000000000000000000000000000000000000001000000000000000000000000ffffde829096dfe8b833997e939865ff57422ea900000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000004172b242d7247fc31d14ce82b32f3ea911808f6f600f362150f9904c974315942927c25f9388cecdbbb0b3723164eea92206775870cd28e1ffd8f1cb9655fb3c4a1b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004186909155a6ba27f173edf15d283da6a0019fb6afe6b223ca68530464813f468f356e70788faf6d1d9ff7bfcfd9021b560d72408bef4c86c66e3a94b9dee0a34a1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000419b2d986652fdebe67554f1b33ae6161b205ea84e0dacb07ffde0889791bcab2e5be3b8229eae01f2c22805c87f15cb7f9642e9cba951489edcac5d12ace399391b00000000000000000000000000000000000000000000000000000000000000").unwrap()
}

pub fn threshold() -> MajorityThreshold {
    let numerator: nonempty::Uint64 = Uint64::from(2u8).try_into().unwrap();
    let denominator: nonempty::Uint64 = Uint64::from(3u8).try_into().unwrap();
    Threshold::try_from((numerator, denominator))
        .unwrap()
        .try_into()
        .unwrap()
}

#[cw_serde]
pub struct TestOperator {
    pub address: Addr,
    pub pub_key: multisig::key::PublicKey,
    pub operator: HexBinary,
    pub weight: Uint128,
    pub signature: Option<Signature>,
}

pub fn operators() -> Vec<TestOperator> {
    [
        (
            "axelar1up3vvhxg4swh2lfeh8n84dat86j6hmgz20d6d3",
            "0312474390012cfbb621c91295dae42b11daaceffbcb7136045c86537a7b37042c",
            "6C51eec96bf0a8ec799cdD0Bbcb4512f8334Afe8",
            1u128,
            None,
        ),
        (
            "axelar10ad5vqhuw2jgp8x6hf59qjjejlna2nh4sfsklc",
            "0315a4c9807fb3e3eb360c6b2cd09ba9edb28b566aaf986b4e107180d89895d42c",
            "7aeB4EEbf1E8DCDE3016d4e1dcA52B4538Cf7aAf",
            1u128,
            Some("72b242d7247fc31d14ce82b32f3ea911808f6f600f362150f9904c974315942927c25f9388cecdbbb0b3723164eea92206775870cd28e1ffd8f1cb9655fb3c4a1b"),
        ),
        (
            "axelar14g0tmk5ldxxdqtl0utl69ck43cpcvd0ay4lfyt",
            "022ffb2327809de022e5aaa651508d397c10d7a2ce60c9115884a295cbab293530",
            "c5b95c99D883c3204CFc2E73669CE3aa7437f4A6",
            1u128,
            Some("86909155a6ba27f173edf15d283da6a0019fb6afe6b223ca68530464813f468f356e70788faf6d1d9ff7bfcfd9021b560d72408bef4c86c66e3a94b9dee0a34a1b"),
        ),
        (
            "axelar1gwd8wd3qkapk8pnwdu4cchah2sjjws6lx694r6",
            "028e02adae730573377cd167095c8b4c63dcc4a2095171ffc9538c7bbbaed31fb2",
            "ffFfDe829096DfE8b833997E939865FF57422Ea9",
            1u128,
            Some("9b2d986652fdebe67554f1b33ae6161b205ea84e0dacb07ffde0889791bcab2e5be3b8229eae01f2c22805c87f15cb7f9642e9cba951489edcac5d12ace399391b"),
        ),
        (
            "axelar1fcrwupthhxm6zsd7kw00w2fk530p6wtt8mj92l",
            "02d1e0cff63aa3e7988e4070242fa37871a9abc79ecf851cce9877297d1316a090",
            "4ef5C8d81b6417fa80c320B5Fc1D3900506dFf54",
            1u128,
            None,
        ),
    ]
        .into_iter()
        .map(
            |(address, pub_key, operator, weight, signature)| TestOperator {
                address: Addr::unchecked(address),
                pub_key: (KeyType::Ecdsa, HexBinary::from_hex(pub_key).unwrap())
                    .try_into()
                    .unwrap(),
                operator: HexBinary::from_hex(operator).unwrap(),
                weight: Uint128::from(weight),
                signature: signature.map(|sig| {
                    (KeyType::Ecdsa, HexBinary::from_hex(sig).unwrap())
                        .try_into()
                        .unwrap()
                }),
            },
        )
        .collect()
}

pub fn quorum() -> Uint128 {
    3u128.into()
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
                    address: Addr::unchecked(format!("verifier{i}")),
                    weight: nonempty::Uint128::one(),
                },
                multisig::key::PublicKey::Ecdsa(HexBinary::from_hex(pub_keys[i]).unwrap()),
            )
        })
        .collect();
    VerifierSet::new(participants, Uint128::from(3u128), 0)
}

// Domain separator matches axelar-gmp-sdk-solidity repo test data
pub fn domain_separator() -> [u8; 32] {
    HexBinary::from_hex("3593643a7d7e917a099eef6c52d1420bb4f33eb074b16439556de5984791262b")
        .unwrap()
        .to_array()
        .unwrap()
}
