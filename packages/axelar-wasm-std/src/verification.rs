use cosmwasm_schema::cw_serde;

#[cw_serde]
#[derive(Copy, Hash, Eq, Ord, PartialOrd)]
pub enum VerificationStatus {
    SucceededOnSourceChain, // message was found and its execution was successful
    FailedOnSourceChain,    // message was found but its execution failed
    NotFoundOnSourceChain,  // message was not found on source chain
    FailedToVerify,         // verification process failed, e.g. no consensus reached
    InProgress,             // verification in progress
    Unknown,                // not verified yet, i.e. has never been part of a poll
}

impl VerificationStatus {
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            VerificationStatus::SucceededOnSourceChain | VerificationStatus::FailedOnSourceChain
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_status_is_confirmed() {
        assert!(VerificationStatus::SucceededOnSourceChain.is_confirmed());
        assert!(VerificationStatus::FailedOnSourceChain.is_confirmed());
        assert!(!VerificationStatus::NotFoundOnSourceChain.is_confirmed());
        assert!(!VerificationStatus::FailedToVerify.is_confirmed());
        assert!(!VerificationStatus::InProgress.is_confirmed());
        assert!(!VerificationStatus::Unknown.is_confirmed());
    }
}
