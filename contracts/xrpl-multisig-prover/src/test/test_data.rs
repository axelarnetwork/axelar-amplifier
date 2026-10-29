use std::collections::{BTreeMap, BTreeSet};

use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::{nonempty, MajorityThreshold, Participant, Threshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::testing::MockApi;
use cosmwasm_std::{Addr, HexBinary, Uint128, Uint64};
use multisig::key::{KeyType, Signature};
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use router_api::{CrossChainId, Message};
use xrpl_types::msg::{XRPLInterchainTransferMessage, XRPLMessage};
use xrpl_types::types::{AxelarSigner, XRPLPaymentAmount};

use crate::axelar_verifiers::VerifierSet as XRPLVerifierSet;

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

pub fn new_xrpl_verifier_set() -> XRPLVerifierSet {
    let signers = vec![
        AxelarSigner {
            address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
            weight: 10u16,
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
                )
                .unwrap(),
            ),
        },
        AxelarSigner {
            address: Addr::unchecked("axelarvaloper1ff675m593vve8yh82lzhdnqfpu7m23cxstr6h4"),
            weight: 10u16,
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "03c6ddb0fcee7b528da1ef3c9eed8d51eeacd7cc28a8baa25c33037c5562faa6e4",
                )
                .unwrap(),
            ),
        },
        AxelarSigner {
            address: Addr::unchecked("axelarvaloper12cwre2gdhyytc3p97z9autzg27hmu4gfzz4rxc"),
            weight: 10u16,
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "0274b5d2a4c55d7edbbf9cc210c4d25adbb6194d6b444816235c82984bee518255",
                )
                .unwrap(),
            ),
        },
        AxelarSigner {
            address: Addr::unchecked("axelarvaloper1vs9rdplntrf7ceqdkznjmanrr59qcpjq6le0yw"),
            weight: 10u16,
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "02a670f57de55b8b39b4cb051e178ca8fb3fe3a78cdde7f8238baf5e6ce1893185",
                )
                .unwrap(),
            ),
        },
        AxelarSigner {
            address: Addr::unchecked("axelarvaloper1hz0slkejw96dukw87fztjkvwjdpcu20jewg6mw"),
            weight: 10u16,
            pub_key: multisig::key::PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "028584592624e742ba154c02df4c0b06e4e8a957ba081083ea9fe5309492aa6c7b",
                )
                .unwrap(),
            ),
        },
    ];

    XRPLVerifierSet {
        signers: BTreeSet::from_iter(signers),
        quorum: 30u32,
        created_at: 1,
    }
}

pub fn incoming_messages() -> Vec<XRPLMessage> {
    vec![XRPLMessage::InterchainTransferMessage(
        XRPLInterchainTransferMessage {
            tx_id: "ff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834"
                .parse()
                .unwrap(),
            transfer_amount: XRPLPaymentAmount::Drops(1_000_000),
            gas_fee_amount: XRPLPaymentAmount::Drops(1_000),
            destination_address: nonempty::String::try_from(
                "A4f10f76B86E01B98daF66A3d02a65e14adb0767",
            )
            .unwrap(),
            destination_chain: "ganache-0".parse().unwrap(),
            source_address: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".parse().unwrap(),
            payload_hash: Some(
                HexBinary::from_hex(
                    "0c3d72390ac0ce0233c551a3c5278f8625ba996f5985dc8d612a9fc55f1de15a",
                )
                .unwrap()
                .to_array::<32>()
                .unwrap(),
            ),
        },
    )]
}

pub fn outgoing_messages() -> Vec<(Message, HexBinary)> {
    vec![(
        Message {
            cc_id: CrossChainId::new(
                "axelar",
                "0x59594d24a88ee8a3ee1e4b41a3cf9d91f0eb9c228c9c3ce0daa16bf48bf6e48a-7669416",
            )
            .unwrap(),
            source_address: "axelar1aqcj54lzz0rk22gvqgcn8fr5tx4rzwdv5wv5j9dmnacgefvd7wzsy2j2mr"
                .parse()
                .unwrap(),
            destination_address: "rNrjh1KGZk2jBR3wPfAQnoidtFFYQKbQn2"
                .parse()
                .unwrap(),
            destination_chain: "xrpl".parse().unwrap(),
            payload_hash: HexBinary::from_hex(
                "03d1b0de4d0c33eacaf2922733a6a92e3ddb47b07517e7674da45cc815a7f869",
            )
            .unwrap()
            .to_array::<32>()
            .unwrap(),
        },
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000087872706c2d65766d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000ba5a21ca88ef6bba2bfff5088994f90e1077e2a1cc3dcc38bd261f00fce2824f00000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000002dc6c0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000147775f5c8cee0da2c0ab059c38eee051d3a3b0fad0000000000000000000000000000000000000000000000000000000000000000000000000000000000000022724b6442644865425646433546693470684d67705a716d5a6d6838374173796156550000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()
    )]
}

pub fn payment_proof() -> HexBinary {
    HexBinary::from_hex("12000022000000002400000000202902a2b7546140000000002dc6c068400000000000014a730081148ebcc02cf59970732ad235dc261183d6d59043598314cc4a1bcb0cc78c44ca6695657a3b6b8e65c89f81f3e010732103d5010607d7f9e85bf00908d3c270eda9ba90903edb2530821b15b04989cef89674463044022030d9990451adf6fceb4e91031b8fc866d4c1950d8ae9e24c85dea71da5683f1602200fcabee302194d94a2c78b06d99c5f17ced1ed010ae1a20324972eb99383626381142424052f757d807256855e79a1abfb63205a31f5e1e01073210301b1b2058a17899d62ff2d242acf133e987ca91b30c69a331cad5a056da817d674473045022100c7ca31d83612f9c99ab5bdf6edce5dedd05e888ccd66389d06a94b091d1f017202201c2e944360bc0641a89c23bb08dfb7bfef47aa98e9c665482fd937d231f3425181148d83d8d3f03a40b3a053f7c749652450720512c2e1e0107321023dbcfa9b9e7cf81348dd2243b1fc408899b00ce7bd5857ddde4f455672064a4474473045022100882f2dedf7651698c316834a0249ca0efb865d10072d8029ed359dcf573624c2022031b709d29169836b69d97b76c010966ceb1d750f51762f20aca8f379940fd7478114944ff4e33f562f654c37d7003d51e33f2d314d2ee1f1f9ea7c04747970657d0570726f6f66e1ea7c10756e7369676e65645f74785f686173687d4038656434373135653261363637383234303334653632336336636138646161393638613063366363373139356538376535343064633366653539323434613634e1ea7c0c736f757263655f636861696e7d066178656c6172e1ea7c0a6d6573736167655f69647d4a3078353935393464323461383865653861336565316534623431613363663964393166306562396332323863396333636530646161313662663438626636653438612d37363639343136e1f1").unwrap()
}

pub fn payment_unsigned_tx_hash() -> HexTxHash {
    HexTxHash::new([
        142, 212, 113, 94, 42, 102, 120, 36, 3, 78, 98, 60, 108, 168, 218, 169, 104, 160, 198, 204,
        113, 149, 232, 126, 84, 13, 195, 254, 89, 36, 74, 100,
    ])
}

pub fn signer_list_set_proof() -> HexBinary {
    HexBinary::from_hex("12000c22000000002402a2b84e20230003555368400000000000014a730081148ebcc02cf59970732ad235dc261183d6d5904359f3e010732103d5010607d7f9e85bf00908d3c270eda9ba90903edb2530821b15b04989cef89674463044022030d9990451adf6fceb4e91031b8fc866d4c1950d8ae9e24c85dea71da5683f1602200fcabee302194d94a2c78b06d99c5f17ced1ed010ae1a20324972eb99383626381142424052f757d807256855e79a1abfb63205a31f5e1e01073210301b1b2058a17899d62ff2d242acf133e987ca91b30c69a331cad5a056da817d674473045022100c7ca31d83612f9c99ab5bdf6edce5dedd05e888ccd66389d06a94b091d1f017202201c2e944360bc0641a89c23bb08dfb7bfef47aa98e9c665482fd937d231f3425181148d83d8d3f03a40b3a053f7c749652450720512c2e1e0107321023dbcfa9b9e7cf81348dd2243b1fc408899b00ce7bd5857ddde4f455672064a4474473045022100882f2dedf7651698c316834a0249ca0efb865d10072d8029ed359dcf573624c2022031b709d29169836b69d97b76c010966ceb1d750f51762f20aca8f379940fd7478114944ff4e33f562f654c37d7003d51e33f2d314d2ee1f1f4eb13ffff81144a24eff7061ce3d81b5c3fd6c1c74542b8055e64e1eb13ffff81142424052f757d807256855e79a1abfb63205a31f5e1eb13ffff81148d83d8d3f03a40b3a053f7c749652450720512c2e1eb13ffff8114944ff4e33f562f654c37d7003d51e33f2d314d2ee1eb13ffff81149e9e9f7f0dbdceadfdaa853c6956025401787647e1f1f9ea7c04747970657d0570726f6f66e1ea7c10756e7369676e65645f74785f686173687d4034366130643161336363313666623264323339356230666431653165316237383562613532346664353863393934346661303565643631646163616165376532e1f1").unwrap()
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
            "axelar12nyeyah0j5ypfywgdd90046jgfl32tycrhlpg6",
            "0308e518015ed6446a2fa10f1fb9735ce89f8c758bad2601373ededd5c1e864b7e",
            "6C51eec96bf0a8ec799cdD0Bbcb4512f8334Afe8",
            65535u128,
            None,
        ),
        (
            "axelar12umz2ds9gvtnkkmcwhukl7lm5asxjc9533dkj8",
            "03d5010607d7f9e85bf00908d3c270eda9ba90903edb2530821b15b04989cef896",
            "7aeB4EEbf1E8DCDE3016d4e1dcA52B4538Cf7aAf",
            65535u128,
            Some("30d9990451adf6fceb4e91031b8fc866d4c1950d8ae9e24c85dea71da5683f160fcabee302194d94a2c78b06d99c5f17ced1ed010ae1a20324972eb993836263"),
        ),
        (
            "axelar13vewqf8exnav577qfdxpf60707yyazsq2hncmx",
            "0301b1b2058a17899d62ff2d242acf133e987ca91b30c69a331cad5a056da817d6",
            "c5b95c99D883c3204CFc2E73669CE3aa7437f4A6",
            65535u128,
            Some("c7ca31d83612f9c99ab5bdf6edce5dedd05e888ccd66389d06a94b091d1f01721c2e944360bc0641a89c23bb08dfb7bfef47aa98e9c665482fd937d231f34251"),
        ),
        (
            "axelar13y07nxqadv3r7fq5hftz2p9rg5f9sgdpn76sf5",
            "023dbcfa9b9e7cf81348dd2243b1fc408899b00ce7bd5857ddde4f455672064a44",
            "ffFfDe829096DfE8b833997E939865FF57422Ea9",
            65535u128,
            Some("882f2dedf7651698c316834a0249ca0efb865d10072d8029ed359dcf573624c231b709d29169836b69d97b76c010966ceb1d750f51762f20aca8f379940fd747"),
        ),
        (
            "axelar14eh260ptse8qsk80ztmeyua9qklhccyv62h9yw",
            "02f95b984a984545c5ff4b77eae5da721c7bcd0380ed941d8ec5ab1c216a4516dc",
            "4ef5C8d81b6417fa80c320B5Fc1D3900506dFf54",
            65535u128,
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
    196605u128.into()
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
