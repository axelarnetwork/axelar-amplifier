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

impl<T: ToBits> AleoBitsToBytesExt for T {}

pub fn bhp<N: Network>(input: impl TryInto<Value<N>>) -> Result<Group<N>, Error> {
    match input.try_into() {
        Ok(value) => Ok(N::hash_to_group_bhp256(&value.to_bits_le())?),
        Err(_) => Err(Error::ConversionFailed),
    }
}
