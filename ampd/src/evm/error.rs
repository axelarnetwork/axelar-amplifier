use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("JSON-RPC error")]
    JsonRPC,
    #[error("block number missing in JSON-RPC response for finalized block")]
    MissBlockNumber,
}
