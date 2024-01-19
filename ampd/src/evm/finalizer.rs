use crate::evm::ChainName;
use async_trait::async_trait;
use error_stack::{self, Report, ResultExt};
use ethers::types::U64;
use mockall::automock;

use super::error::Error;
use crate::evm::json_rpc::EthereumClient;

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait Finalizer: Send + Sync {
    async fn latest_finalized_block_height(&self) -> Result<U64>;
}

pub fn pick<'a, C, H>(
    chain: &'a ChainName,
    rpc_client: &'a C,
    confirmation_height: H,
) -> Box<dyn Finalizer + 'a>
where
    C: EthereumClient + Send + Sync,
    H: Into<U64>,
{
    match chain {
        ChainName::Ethereum => Box::new(EthereumFinalizer::new(rpc_client)),
        ChainName::Other(_) => Box::new(PoWFinalizer::new(rpc_client, confirmation_height)),
    }
}

pub struct EthereumFinalizer<'a, C>
where
    C: EthereumClient,
{
    rpc_client: &'a C,
}

impl<'a, C> EthereumFinalizer<'a, C>
where
    C: EthereumClient,
{
    pub fn new(rpc_client: &'a C) -> Self {
        EthereumFinalizer { rpc_client }
    }
}

#[async_trait]
impl<'a, C> Finalizer for EthereumFinalizer<'a, C>
where
    C: EthereumClient + Send + Sync,
{
    async fn latest_finalized_block_height(&self) -> Result<U64> {
        self.rpc_client
            .finalized_block()
            .await
            .change_context(Error::JsonRPC)?
            .number
            .ok_or_else(|| Report::new(Error::MissBlockNumber))
    }
}

pub struct PoWFinalizer<'a, C>
where
    C: EthereumClient,
{
    rpc_client: &'a C,
    confirmation_height: U64,
}

impl<'a, C> PoWFinalizer<'a, C>
where
    C: EthereumClient,
{
    pub fn new<H>(rpc_client: &'a C, confirmation_height: H) -> Self
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
impl<'a, C> Finalizer for PoWFinalizer<'a, C>
where
    C: EthereumClient + Send + Sync,
{
    async fn latest_finalized_block_height(&self) -> Result<U64> {
        let block_number = self
            .rpc_client
            .block_number()
            .await
            .change_context(Error::JsonRPC)?;

        Ok(block_number - self.confirmation_height + 1)
    }
}

#[cfg(test)]
mod tests {
    use crate::evm::finalizer::{Finalizer, PoWFinalizer};
    use crate::evm::json_rpc::MockEthereumClient;
    use ethers::types::U64;
    use tokio::test;

    #[test]
    async fn latest_finalized_block_height_should_work() {
        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        rpc_client
            .expect_block_number()
            .returning(move || Ok(block_number));
        assert_eq!(
            block_number,
            PoWFinalizer::new(&rpc_client, 1)
                .latest_finalized_block_height()
                .await
                .unwrap()
        );

        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        rpc_client
            .expect_block_number()
            .returning(move || Ok(block_number));
        assert_eq!(
            block_number + 1,
            PoWFinalizer::new(&rpc_client, 0)
                .latest_finalized_block_height()
                .await
                .unwrap()
        );

        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        rpc_client
            .expect_block_number()
            .returning(move || Ok(block_number));
        assert_eq!(
            block_number - 1,
            PoWFinalizer::new(&rpc_client, 2)
                .latest_finalized_block_height()
                .await
                .unwrap()
        );

        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        rpc_client
            .expect_block_number()
            .returning(move || Ok(block_number));
        assert_eq!(
            U64::from(1),
            PoWFinalizer::new(&rpc_client, block_number)
                .latest_finalized_block_height()
                .await
                .unwrap()
        );
    }
}
