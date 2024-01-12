use cosmwasm_schema::cw_serde;

#[cw_serde]
#[derive(Copy)]
pub enum VerificationStatus {
    SucceededOnChain,
    FailedOnChain,
    NotFound,
    FailedToVerify, // verification process failed, e.g. no consensus reached
    InProgress,     // verification in progress
    NotVerified,    // not yet verified, e.g. not in a poll
}
