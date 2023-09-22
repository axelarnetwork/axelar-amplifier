use fastcrypto::encoding::{Base58, Encoding};

use crate::sui::error::Error;

pub struct TransactionDigest([u8; 32]);

impl TransactionDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub fn base58_encode(&self) -> String {
        Base58::encode(self.0)
    }
}

impl std::str::FromStr for TransactionDigest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = [0; 32];
        result.copy_from_slice(&Base58::decode(s).map_err(|_| Error::InvalidTransactionDigest)?);

        Ok(TransactionDigest::new(result))
    }
}
