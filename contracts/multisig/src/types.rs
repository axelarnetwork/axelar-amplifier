use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;

use crate::ContractError;

#[cw_serde]
pub struct MsgToSign(HexBinary);

impl From<MsgToSign> for HexBinary {
    fn from(original: MsgToSign) -> Self {
        original.0
    }
}

impl AsRef<[u8]> for MsgToSign {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl MsgToSign {
    pub fn unchecked(hex: HexBinary) -> Self {
        Self(hex)
    }
}

#[cw_serde]
pub enum MultisigState {
    Pending,
    Completed {
        completed_at: u64, // block at which the session was completed
    },
}

const MESSAGE_HASH_LEN: usize = 32;

impl TryFrom<HexBinary> for MsgToSign {
    type Error = ContractError;

    fn try_from(other: HexBinary) -> Result<Self, Self::Error> {
        if other.len() != MESSAGE_HASH_LEN {
            return Err(ContractError::InvalidMessageFormat {
                reason: "Invalid input length".into(),
            });
        }

        Ok(MsgToSign::unchecked(other))
    }
}

#[cfg(test)]
mod tests {
    use crate::test::common::ecdsa_test_data;

    use super::*;

    #[test]
    fn test_try_from_hexbinary_to_message() {
        let hex = ecdsa_test_data::message();
        let message = MsgToSign::try_from(hex.clone()).unwrap();
        assert_eq!(HexBinary::from(message), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_message_fails() {
        let hex = HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap();
        assert_eq!(
            MsgToSign::try_from(hex.clone()).unwrap_err(),
            ContractError::InvalidMessageFormat {
                reason: "Invalid input length".into()
            }
        );
    }
}
