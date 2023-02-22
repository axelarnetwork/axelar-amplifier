use crate::evm::json_rpc::EthereumClient;

use super::error::Error;
use async_trait::async_trait;
use error_stack::{self, ResultExt};
use mockall::automock;
use web3::types::U64;

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait Finalizer {
    async fn latest_finalized_block_height(&self) -> Result<U64>;
}

pub struct PoWFinalizer<C>
where
    C: EthereumClient,
{
    rpc_client: C,
    confirmation_height: U64,
}

impl<C> PoWFinalizer<C>
where
    C: EthereumClient,
{
    pub fn new<H>(rpc_client: C, confirmation_height: H) -> Self
    where
        H: Into<U64>,
    {
        PoWFinalizer {
            rpc_client,
            confirmation_height: confirmation_height.into(),
        }
    }
}

#[async_trait]
impl<C> Finalizer for PoWFinalizer<C>
where
    C: EthereumClient + Send + Sync,
{
    async fn latest_finalized_block_height(&self) -> Result<U64> {
        let block_number = self
            .rpc_client
            .block_number()
            .await
            .change_context(Error::JSONRPCError)?;

        Ok(block_number - self.confirmation_height + 1)
    }
}

#[cfg(test)]
mod tests {
    use crate::evm::finalizer::{Finalizer, PoWFinalizer};
    use crate::evm::json_rpc::MockEthereumClient;
    use tokio::test;
    use web3::types::U64;

    #[test]
    async fn latest_finalized_block_height_should_work() {
        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        rpc_client.expect_block_number().returning(move || Ok(block_number));
        assert_eq!(
            block_number,
            PoWFinalizer::new(rpc_client, 1)
                .latest_finalized_block_height()
                .await
                .unwrap()
        );

        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        rpc_client.expect_block_number().returning(move || Ok(block_number));
        assert_eq!(
            block_number + 1,
            PoWFinalizer::new(rpc_client, 0)
                .latest_finalized_block_height()
                .await
                .unwrap()
        );

        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        rpc_client.expect_block_number().returning(move || Ok(block_number));
        assert_eq!(
            block_number - 1,
            PoWFinalizer::new(rpc_client, 2)
                .latest_finalized_block_height()
                .await
                .unwrap()
        );

        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        rpc_client.expect_block_number().returning(move || Ok(block_number));
        assert_eq!(
            U64::from(1),
            PoWFinalizer::new(rpc_client, block_number)
                .latest_finalized_block_height()
                .await
                .unwrap()
        );
    }
}
