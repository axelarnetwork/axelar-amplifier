//! Module for the [`PubkeyWrapper`] type.

use std::ops::Deref;

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

/// Wrapper type used to implement Borsh traits for [`Pubkey`]
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubkeyWrapper(Pubkey);

impl From<Pubkey> for PubkeyWrapper {
    fn from(value: Pubkey) -> Self {
        Self(value)
    }
}

impl Deref for PubkeyWrapper {
    type Target = Pubkey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BorshDeserialize for PubkeyWrapper {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let inner: [u8; 32] = <[u8; 32]>::deserialize_reader(reader)?;
        Ok(PubkeyWrapper(inner.into()))
    }
}

impl BorshSerialize for PubkeyWrapper {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        <[u8; 32]>::serialize(&self.0.to_bytes(), writer)
    }
}
