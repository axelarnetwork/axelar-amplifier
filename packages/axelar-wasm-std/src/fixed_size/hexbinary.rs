use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::Deref;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::StdResult;
use cw_storage_plus::{Key, KeyDeserialize, Prefixer, PrimaryKey};

use crate::fixed_size::Error;

/// A HexBinary wrapper that enforces a fixed length at compile time
#[cw_serde]
#[serde(try_from = "cosmwasm_std::HexBinary")]
#[derive(Eq, Hash)]
pub struct HexBinary<const N: usize>(cosmwasm_std::HexBinary, PhantomData<[u8; N]>);

impl<const N: usize> TryFrom<cosmwasm_std::HexBinary> for HexBinary<N> {
    type Error = Error;

    fn try_from(value: cosmwasm_std::HexBinary) -> Result<Self, Self::Error> {
        if value.len() != N {
            Err(Error::InvalidLength {
                expected: N,
                actual: value.len(),
            })
        } else {
            Ok(HexBinary(value, PhantomData))
        }
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for HexBinary<N> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        cosmwasm_std::HexBinary::from(value).try_into()
    }
}

impl<const N: usize> TryFrom<&[u8]> for HexBinary<N> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        cosmwasm_std::HexBinary::from(value).try_into()
    }
}

impl<const N: usize> TryFrom<[u8; N]> for HexBinary<N> {
    type Error = Error;

    fn try_from(value: [u8; N]) -> Result<Self, Self::Error> {
        cosmwasm_std::HexBinary::from(value.as_slice()).try_into()
    }
}

impl<const N: usize> From<HexBinary<N>> for cosmwasm_std::HexBinary {
    fn from(value: HexBinary<N>) -> Self {
        value.0
    }
}

impl<const N: usize> From<HexBinary<N>> for Vec<u8> {
    fn from(value: HexBinary<N>) -> Self {
        value.0.into()
    }
}

impl<const N: usize> TryFrom<HexBinary<N>> for [u8; N] {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: HexBinary<N>) -> Result<Self, Self::Error> {
        let vec: Vec<u8> = value.into();
        vec.as_slice().try_into()
    }
}

impl<const N: usize> Deref for HexBinary<N> {
    type Target = cosmwasm_std::HexBinary;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> Display for HexBinary<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<const N: usize> PrimaryKey<'_> for HexBinary<N> {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_slice())]
    }
}

impl<const N: usize> Prefixer<'_> for HexBinary<N> {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_slice())]
    }
}

impl<const N: usize> KeyDeserialize for HexBinary<N> {
    type Output = Self;
    const KEY_ELEMS: u16 = 1;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        HexBinary::try_from(cosmwasm_std::HexBinary::from(value))
            .map_err(|e| cosmwasm_std::StdError::generic_err(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use cosmwasm_std::StdError;

    use super::*;

    #[test]
    fn test_fixed_size_hexbinary_correct_length() {
        let data = vec![1u8; 20];
        let hex = cosmwasm_std::HexBinary::from(data);
        assert_ok!(HexBinary::<20>::try_from(hex));
    }

    #[test]
    fn test_fixed_size_hexbinary_wrong_length() {
        let data = vec![1u8; 19];
        let hex = cosmwasm_std::HexBinary::from(data);
        let result = HexBinary::<20>::try_from(hex);

        assert_eq!(
            result.unwrap_err(),
            Error::InvalidLength {
                expected: 20,
                actual: 19
            }
        );
    }

    #[test]
    fn test_from_array() {
        let data = [1u8; 20];
        assert_ok!(HexBinary::<20>::try_from(data));
    }

    #[test]
    fn test_from_slice() {
        let data = [1u8; 20];
        assert_ok!(HexBinary::<20>::try_from(data.as_slice()));
    }

    #[test]
    fn test_from_vec() {
        let data = vec![1u8; 20];
        assert_ok!(HexBinary::<20>::try_from(data));
    }

    #[test]
    fn test_to_array() {
        let data = [1u8; 20];
        let hex = HexBinary::<20>::try_from(data).unwrap();
        let result: [u8; 20] = hex.try_into().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_different_sizes() {
        let evm_addr_data = vec![1u8; 20];
        assert_ok!(HexBinary::<20>::try_from(evm_addr_data));

        let hash_data = vec![1u8; 32];
        assert_ok!(HexBinary::<32>::try_from(hash_data));
    }

    #[test]
    fn test_display() {
        let data = vec![0x01, 0x23, 0x45];
        let hex = HexBinary::<3>::try_from(data).unwrap();
        assert_eq!(format!("{}", hex), "012345");
    }

    #[test]
    fn test_key_deserialize_error() {
        let data = vec![1u8; 19]; // Wrong length
        let result = HexBinary::<20>::from_vec(data);
        assert!(result.is_err());

        if let Err(StdError::GenericErr { msg, .. }) = result {
            assert!(msg.contains("expected length 20, got 19"));
        } else {
            panic!("Expected GenericErr");
        }
    }
}
