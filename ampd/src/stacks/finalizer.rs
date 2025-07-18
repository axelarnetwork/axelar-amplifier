use error_stack::{self};
use ethers_core::types::U64;

use crate::stacks::http_client::{Client, Error};

pub async fn latest_finalized_block_height<H>(
    http_client: &Client,
    confirmation_height: H,
) -> error_stack::Result<u64, Error>
where
    H: Into<U64>,
{
    let block = http_client.latest_block().await?;

    let block_number: U64 = block.height.into();

    // order of operations is important here when saturating, otherwise the finalization window could be cut short
    // if we add 1 afterwards
    Ok(block_number
        .saturating_add(U64::from(1))
        .saturating_sub(confirmation_height.into())
        .as_u64())
}

#[cfg(test)]
mod tests {
    use tokio::test as async_test;

    use crate::stacks::finalizer::latest_finalized_block_height;
    use crate::stacks::http_client::{Block, Client};

    #[async_test]
    async fn latest_finalized_block_height_should_work() {
        let mut client = Client::faux();
        faux::when!(client.latest_block).then(|_| Ok(Block { height: 10 }));

        assert_eq!(10, latest_finalized_block_height(&client, 1).await.unwrap());

        assert_eq!(11, latest_finalized_block_height(&client, 0).await.unwrap());

        assert_eq!(9, latest_finalized_block_height(&client, 2).await.unwrap());

        assert_eq!(1, latest_finalized_block_height(&client, 10).await.unwrap());
    }
}
