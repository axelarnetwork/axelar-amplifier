use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed parsing ABCI event")]
    ParseEventError,
    #[error("JSON-RPC error")]
    JSONRPCError,
}
