use std::str::FromStr;

use aleo_compatible_keccak::ToBytesExt;
use cosmwasm_std::{Addr, HexBinary, Uint128};
use multisig::key::{KeyType, PublicKey};

use super::test_data::TestOperator;

pub fn operators() -> Vec<TestOperator> {
    [
        (
            "axelar1up3vvhxg4swh2lfeh8n84dat86j6hmgz20d6d3",
            "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px",
            "6C51eec96bf0a8ec799cdD0Bbcb4512f8334Afe8",
            1u128,
            None,
        ),
        (
            "axelar10ad5vqhuw2jgp8x6hf59qjjejlna2nh4sfsklc",
            "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t",
            "7aeB4EEbf1E8DCDE3016d4e1dcA52B4538Cf7aAf",
            1u128,
            Some("72b242d7247fc31d14ce82b32f3ea911808f6f600f362150f9904c974315942927c25f9388cecdbbb0b3723164eea92206775870cd28e1ffd8f1cb9655fb3c4a1b"),
        ),
        (
            "axelar14g0tmk5ldxxdqtl0utl69ck43cpcvd0ay4lfyt",
            "aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg",
            "c5b95c99D883c3204CFc2E73669CE3aa7437f4A6",
            1u128,
            Some("86909155a6ba27f173edf15d283da6a0019fb6afe6b223ca68530464813f468f356e70788faf6d1d9ff7bfcfd9021b560d72408bef4c86c66e3a94b9dee0a34a1b"),
        ),
        (
            "axelar1gwd8wd3qkapk8pnwdu4cchah2sjjws6lx694r6",
            "aleo12ux3gdauck0v60westgcpqj7v8rrcr3v346e4jtq04q7kkt22czsh808v2",
            "ffFfDe829096DfE8b833997E939865FF57422Ea9",
            1u128,
            Some("9b2d986652fdebe67554f1b33ae6161b205ea84e0dacb07ffde0889791bcab2e5be3b8229eae01f2c22805c87f15cb7f9642e9cba951489edcac5d12ace399391b"),
        ),
    ]
        .into_iter()
        .map(
            |(address, pub_key, operator, weight, signature)| {
                TestOperator {
                address: Addr::unchecked(address),
                pub_key: (KeyType::AleoSchnorr, HexBinary::from(PublicKey::AleoSchnorr(
                    HexBinary::from(snarkvm_cosmwasm::prelude::Address::<snarkvm_cosmwasm::prelude::TestnetV0>::from_str(pub_key)
                        .unwrap()
                        .to_bytes_le_array::<{ aleo_gmp_types::ALEO_ADDRESS_LENGTH }>()
                        .unwrap()),
                ))).try_into().unwrap(),
                operator: HexBinary::from_hex(operator).unwrap(),
                weight: Uint128::from(weight),
                signature: signature.map(|sig| {
                    (KeyType::AleoSchnorr, HexBinary::from_hex(sig).unwrap())
                        .try_into()
                        .unwrap()
                }),
            }},
        )
        .collect()
}
