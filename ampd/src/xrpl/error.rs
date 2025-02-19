use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("JSON-RPC error")]
    JsonRPC,
    #[error("ledger index missing in JSON-RPC response for validated ledger")]
    MissLedgerIndex,
}
