use cosmwasm_schema::cw_serde;

#[cw_serde]
#[derive(Copy)]
pub enum VerificationStatus {
    SucceededOnChain,
    FailedOnChain,
    NotFound,
    FailedToVerify,
    InProgress,  // still in an open poll
    NotVerified, // not in a poll
}
