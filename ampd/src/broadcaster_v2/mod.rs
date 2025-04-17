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
    EnqueueMsg(#[from] mpsc::error::SendError<msg_queue::QueueMsg>),
    #[error("failed to estimate gas")]
    EstimateGas,
    #[error("failed to query account")]
    QueryAccount,
    #[error("invalid public key")]
    InvalidPubKey,
}

#[derive(TypedBuilder)]
pub struct Broadcaster<T, Q, S>
where
    T: cosmos::CosmosClient + Clone,
    Q: Stream<Item = Vec<msg_queue::QueueMsg>>,
    S: Multisig,
{
    cosmos_client: T,
    account_manager: account::AccountManager<T>,
    msg_queue: Q,
    signer: S,
}

impl<T, Q, S> Broadcaster<T, Q, S>
where
    T: cosmos::CosmosClient + Clone,
    Q: Stream<Item = Vec<msg_queue::QueueMsg>>,
    S: Multisig,
{
    pub async fn run(self) -> Result<()> {
        todo!()
    }
}
