#[cfg(test)]
mod tests {

    use solana_sdk::{pubkey::Pubkey, signature::Signature};
    use solana_transaction_status::UiTransactionEncoding;
    use std::str::FromStr;
    use tokio::test as async_test;

    const RPC_URL: &str = "http://127.0.0.1:8899"; // default.

    #[ignore = "Exploratory test, still not intended to run in CI"]
    #[async_test]
    async fn test_get_transaction_works() {
        let rpc_client =
            solana_client::nonblocking::rpc_client::RpcClient::new(RPC_URL.to_string());

        let tx = rpc_client
            .get_transaction(
                &Signature::from_str("3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP").unwrap(),
                UiTransactionEncoding::JsonParsed,
            )
            .await.unwrap();

        println!("tx - {:?}", tx.transaction);
    }

    #[ignore = "Exploratory test, still not intended to run in CI"]
    #[async_test]
    async fn test_get_account_data_works() {
        let rpc_client =
            solana_client::nonblocking::rpc_client::RpcClient::new(RPC_URL.to_string());
        let acc = rpc_client
            .get_account_data(
                &Pubkey::from_str("EHgEeD1Z3pc29s3JKhfVv9AGk7HkQFZKkcHbkypdN1h6").unwrap(),
            )
            .await
            .unwrap();
        println!("acc - {:?}", acc);
    }
}
