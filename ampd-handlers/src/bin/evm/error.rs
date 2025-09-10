use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to load configuration")]
    Config,
    #[error("grpc call failed")]
    Grpc,
    #[error("failed to handle event")]
    EventHandling,
    #[error("handler task failed")]
    HandlerTask,
    #[error("failed to get the latest finalized block")]
    Finalizer,
    #[error("failed to connect to the RPC endpoint")]
    RpcConnection,
}
