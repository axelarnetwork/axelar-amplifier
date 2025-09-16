use std::ops::{Deref, Index};

use interchain_token_service_std::TokenId;

/// Internal wrapper for converting between ITS TokenId and Aleo's u128 pair format.
///
/// ITS uses 32-byte token IDs for cross-chain compatibility, while Aleo programs
/// work with pairs of u128 values. This newtype provides bidirectional conversion
/// between these formats while preserving the original token ID semantics.
///
/// ## Format Details
///
/// - **ITS Format**: 32 bytes (256 bits) as `[u8; 32]`
/// - **Aleo Format**: 2 × u128 values as `[u128; 2]`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItsTokenIdNewType(pub [u128; 2]);

impl From<ItsTokenIdNewType> for TokenId {
    /// Converts from Aleo's u128 pair format back to ITS TokenId.
    fn from(value: ItsTokenIdNewType) -> Self {
        let result = bytemuck::cast::<[u128; 2], [u8; 32]>(value.0);

        TokenId::new(result)
    }
}

impl From<TokenId> for ItsTokenIdNewType {
    /// Converts from ITS TokenId to Aleo's u128 pair format.
    fn from(value: TokenId) -> Self {
        let input: [u8; 32] = value.into();
        let result = bytemuck::cast::<[u8; 32], [u128; 2]>(input);

        ItsTokenIdNewType(result)
    }
}

impl Index<usize> for ItsTokenIdNewType {
    type Output = u128;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl Deref for ItsTokenIdNewType {
    type Target = [u128; 2];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
