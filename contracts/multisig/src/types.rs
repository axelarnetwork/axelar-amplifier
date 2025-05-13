use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;


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

#[cfg(any(test, feature = "test"))]
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


impl From<HexBinary> for MsgToSign {
    fn from(value: HexBinary) -> Self {
        MsgToSign(value)
    }
}

