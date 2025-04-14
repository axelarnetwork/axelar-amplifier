use futures::Stream;
use thiserror::Error;
use tokio::sync::mpsc;
use typed_builder::TypedBuilder;

use crate::cosmos;
use crate::tofnd::grpc::Multisig;

mod account;
mod msg_queue;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to enqueue message")]
    EnqueueMsg(#[from] mpsc::error::SendError<msg_queue::Msg>),
    #[error("failed to estimate gas")]
    EstimateGas,
    #[error("failed to query account")]
    QueryAccount,
    #[error("invalid public key")]
    InvalidPubKey,
    #[error("integer overflow")]
    IntegerOverflow,
}

#[derive(TypedBuilder)]
pub struct TxBroadcaster<T, A, Q, S>
where
    T: cosmos::CosmosClient,
    A: account::AccountManager,
    Q: Stream<Item = Vec<msg_queue::Msg>>,
    S: Multisig,
{
    cosmos_client: T,
    account_manager: A,
    msg_queue: Q,
    signer: S,
}

impl<T, A, Q, S> TxBroadcaster<T, A, Q, S>
where
    T: cosmos::CosmosClient,
    A: account::AccountManager,
    Q: Stream<Item = Vec<msg_queue::Msg>>,
    S: Multisig,
{
    pub async fn run(self) -> Result<()> {
        todo!()
    }
}
