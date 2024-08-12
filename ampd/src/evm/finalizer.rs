use async_trait::async_trait;
use error_stack::{self, Report, ResultExt};
use ethers_core::types::U64;
use mockall::automock;
use serde::{Deserialize, Serialize};

use super::error::Error;
use crate::evm::json_rpc::EthereumClient;

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait Finalizer: Send + Sync {
    async fn latest_finalized_block_height(&self) -> Result<U64>;
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Default)]
pub enum Finalization {
    #[default]
    RPCFinalizedBlock,
    ConfirmationHeight,
}

pub fn pick<'a, C, H>(
    finalizer_type: &'a Finalization,
    rpc_client: &'a C,
    confirmation_height: H,
) -> Box<dyn Finalizer + 'a>
where
    C: EthereumClient + Send + Sync,
    H: Into<U64>,
{
    match finalizer_type {
        Finalization::RPCFinalizedBlock => Box::new(RPCFinalizer::new(rpc_client)),
        Finalization::ConfirmationHeight => Box::new(ConfirmationHeightFinalizer::new(
            rpc_client,
            confirmation_height,
        )),
    }
}

pub struct RPCFinalizer<'a, C>
where
    C: EthereumClient,
{
    rpc_client: &'a C,
}

impl<'a, C> RPCFinalizer<'a, C>
where
    C: EthereumClient,
{
    pub fn new(rpc_client: &'a C) -> Self {
        RPCFinalizer { rpc_client }
    }
}

#[async_trait]
impl<'a, C> Finalizer for RPCFinalizer<'a, C>
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

pub struct ConfirmationHeightFinalizer<'a, C>
where
    C: EthereumClient,
{
    rpc_client: &'a C,
    confirmation_height: U64,
}

impl<'a, C> ConfirmationHeightFinalizer<'a, C>
where
    C: EthereumClient,
{
    pub fn new<H>(rpc_client: &'a C, confirmation_height: H) -> Self
    where
        H: Into<U64>,
    {
        ConfirmationHeightFinalizer {
            rpc_client,
            confirmation_height: confirmation_height.into(),
        }
    }
}

#[async_trait]
impl<'a, C> Finalizer for ConfirmationHeightFinalizer<'a, C>
where
    C: EthereumClient + Send + Sync,
{
    async fn latest_finalized_block_height(&self) -> Result<U64> {
        let block_number = self
            .rpc_client
            .block_number()
            .await
            .change_context(Error::JsonRPC)?;

        // order of operations is important here when saturating, otherwise the finalization window could be cut short
        // if we add 1 afterwards
        Ok(block_number
            .saturating_add(U64::from(1))
            .saturating_sub(self.confirmation_height))
    }
}

#[cfg(test)]
mod tests {
    use ethers_core::abi::Hash;
    use ethers_core::types::{Block, U64};
    use tokio::test;

    use crate::evm::finalizer::{pick, ConfirmationHeightFinalizer, Finalization, Finalizer};
    use crate::evm::json_rpc::MockEthereumClient;

    #[test]
    async fn latest_finalized_block_height_should_work() {
        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        rpc_client
            .expect_block_number()
            .returning(move || Ok(block_number));
        assert_eq!(
            block_number,
            ConfirmationHeightFinalizer::new(&rpc_client, 1)
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
            ConfirmationHeightFinalizer::new(&rpc_client, 0)
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
            ConfirmationHeightFinalizer::new(&rpc_client, 2)
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
            ConfirmationHeightFinalizer::new(&rpc_client, block_number)
                .latest_finalized_block_height()
                .await
                .unwrap()
        );
    }

    #[test]
    async fn pick_should_work_for_ethereum_finalizer() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        let finalizer = pick(&Finalization::RPCFinalizedBlock, &rpc_client, 1);
        assert_eq!(
            finalizer.latest_finalized_block_height().await.unwrap(),
            block_number
        );
    }

    #[test]
    async fn pick_should_work_for_pow_finalizer() {
        let mut rpc_client = MockEthereumClient::new();
        let block_number: U64 = 10.into();
        let pow_confirmation_height = 6;

        rpc_client
            .expect_block_number()
            .returning(move || Ok(block_number));

        let finalizer = pick(
            &Finalization::ConfirmationHeight,
            &rpc_client,
            pow_confirmation_height,
        );
        assert_eq!(
            finalizer.latest_finalized_block_height().await.unwrap(),
            block_number - U64::from(pow_confirmation_height - 1)
        );
    }
}
