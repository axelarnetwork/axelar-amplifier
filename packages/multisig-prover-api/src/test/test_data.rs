use axelar_wasm_std::{nonempty, Participant};
use cosmwasm_std::testing::MockApi;
use cosmwasm_std::{HexBinary, Uint128};
use multisig::verifier_set::VerifierSet;
use router_api::{CrossChainId, Message};

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