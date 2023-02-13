use super::error::Error;
use async_trait::async_trait;
use mockall::automock;
use web3::types::U64;

#[automock]
#[async_trait]
pub trait Finalizer: Send + Sync + 'static {
    async fn latest_finalized_block_height(&self) -> Result<U64, Error>;
}
