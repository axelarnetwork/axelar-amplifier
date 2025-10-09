use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to deserialize the event")]
    DeserializeEvent,
    #[error("failed to fetch Solana account")]
    FetchSolanaAccount,
    #[error("failed to get the latest finalized block")]
    Finalizer,
    #[error("failed to prepare message for signing")]
    MessageToSign,
    #[error("failed to parse public key")]
    PublicKey,
    #[error("failed to get signature from tofnd")]
    Sign,
    #[error("failed to get transaction receipts")]
    TxReceipts,
}
