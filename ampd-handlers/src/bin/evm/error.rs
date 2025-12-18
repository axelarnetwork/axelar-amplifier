use axelar_wasm_std::chain::ChainName;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("handler failed to start")]
    HandlerStart,
    #[error("event verifier contract not found in contracts response")]
    EventVerifierContractNotFound,
    #[error("missing confirmation height in config. event verification handler requires confirmation height when finalization is ConfirmationHeight")]
    MissingConfirmationHeight,
    #[error("handler task failed")]
    HandlerTask,
    #[error("task group execution failed")]
    TaskGroup,
    #[error("faild to establish RPC connection for chain {0}")]
    RpcConnection(ChainName),
}
