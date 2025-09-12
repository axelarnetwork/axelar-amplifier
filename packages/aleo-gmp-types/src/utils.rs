use snarkvm_cosmwasm::prelude::{Group, Network, ToBits, ToBytes, Value};

use crate::error::Error;

pub const ALEO_ADDRESS_LENGTH: usize = 32; // 32 bytes

/// SnarkVM implement `ToBytes` trait for most of there types.
/// We need to convert the Hash to 256 bits to use it in Axelar GMP protocol.
pub trait ToBytesExt: ToBytes {
    fn to_bytes_le_array<const N: usize>(&self) -> Result<[u8; N], Error>
    where
        Self: Sized,
    {
        let bytes = self.to_bytes_le()?;
        bytes.try_into().map_err(|_| Error::ConversionFailed)
    }
}

impl<T: ToBytes> ToBytesExt for T {}

pub trait AleoBitsToBytesExt: ToBits {
    fn to_bytes(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        let bits = self.to_bits_le();
        let vec_len = (bits.len().saturating_add(7)).saturating_div(8);
        bits.iter()
            .enumerate()
            .fold(vec![0u8; vec_len], |mut acc, (i, &bit)| {
                if bit {
                    acc[i / 8] |= 1 << (i % 8);
                }
                acc
            })
    }
}

pub fn from_bytes(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
        .collect()
}

impl<T: ToBits> AleoBitsToBytesExt for T {}

pub fn bhp<N: Network>(input: impl TryInto<Value<N>>) -> Result<Group<N>, Error> {
    match input.try_into() {
        Ok(value) => Ok(N::hash_to_group_bhp256(&value.to_bits_le())?),
        Err(_) => Err(Error::ConversionFailed),
    }
}

#[cfg(test)]
mod tests {
    use snarkvm_cosmwasm::prelude::{FromBits as _, Plaintext};
    use std::str::FromStr as _;

    use super::*;

    type CurrentNetwork = snarkvm_cosmwasm::prelude::TestnetV0;

    #[test]
    fn test_to_bytes_le_array() {
        let data = r#"{
            caller: aleo1ymrcwun5g9z0un8dqgdln7l3q77asqr98p7wh03dwgk4yfltpqgq9efvfz,
            destination_chain: [
                129560248324330402842460762574046625792u128,
                0u128
            ],
            destination_address: [
                129560248324330635220088419148146701675u128,
                146767682061739132652181577970743343734u128,
                67091725296194228626838386705843189365u128,
                141160062220609416535136629668810482795u128,
                69119855780815625390997967134577917952u128,
                0u128
            ],
            payload_hash: 7891287054814271187580465323074959471075012157317252794588013286624830010585field
        }"#;
        let expected_value = Value::<CurrentNetwork>::from_str(data).unwrap();
        let serialize = expected_value.to_bytes();

        let deserialize = from_bytes(&serialize);

        let value = Value::from(Plaintext::from_bits_le(&deserialize).unwrap());

        assert_eq!(expected_value, value);
    }
}
