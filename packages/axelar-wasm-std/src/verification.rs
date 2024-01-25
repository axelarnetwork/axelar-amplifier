use cosmwasm_schema::cw_serde;

#[cw_serde]
#[derive(Copy)]
pub enum VerificationStatus {
    SucceededOnChain,
    FailedOnChain,
    NotFound,
    FailedToVerify, // verification process failed, e.g. no consensus reached
    InProgress,     // verification in progress
    None,           // not yet verified, e.g. not in a poll
}

impl VerificationStatus {
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            VerificationStatus::SucceededOnChain | VerificationStatus::FailedOnChain
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_status_is_confirmed() {
        assert!(VerificationStatus::SucceededOnChain.is_confirmed());
        assert!(VerificationStatus::FailedOnChain.is_confirmed());
        assert!(!VerificationStatus::NotFound.is_confirmed());
        assert!(!VerificationStatus::FailedToVerify.is_confirmed());
        assert!(!VerificationStatus::InProgress.is_confirmed());
        assert!(!VerificationStatus::None.is_confirmed());
    }
}
