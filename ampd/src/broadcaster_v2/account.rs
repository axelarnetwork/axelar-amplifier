use std::sync::Arc;

use error_stack::ResultExt;
use report::ResultCompatExt;
use tokio::sync::RwLock;

use super::{Error, Result};
use crate::types::{CosmosPublicKey, TMAddress};
use crate::{cosmos, PREFIX};

#[derive(Clone)]
pub struct AccountManager<T>
where
    T: cosmos::CosmosClient,
{
    client: T,
    pub_key: CosmosPublicKey,
    address: TMAddress,
    account_number: u64,
    curr_sequence: Arc<RwLock<u64>>,
}

impl<T> AccountManager<T>
where
    T: cosmos::CosmosClient,
{
    pub async fn new(mut client: T, pub_key: CosmosPublicKey) -> Result<Self>
    where
        T: cosmos::CosmosClient,
    {
        let address = pub_key
            .account_id(PREFIX)
            .change_context(Error::InvalidPubKey)?
            .into();
        cosmos::account(&mut client, &address)
            .await
            .map(|account| Self {
                client,
                pub_key,
                address,
                account_number: account.account_number,
                curr_sequence: Arc::new(RwLock::new(account.sequence)),
            })
            .change_context(Error::QueryAccount)
    }
}

impl<T> AccountManager<T>
where
    T: cosmos::CosmosClient,
{
    pub fn pub_key(&self) -> CosmosPublicKey {
        self.pub_key
    }

    pub fn address(&self) -> TMAddress {
        self.address.clone()
    }

    pub fn account_number(&self) -> u64 {
        self.account_number
    }

    pub async fn curr_sequence(&self) -> u64 {
        *self.curr_sequence.read().await
    }

    pub async fn curr_sequence_and_incr(&self) -> u64 {
        let mut curr_sequence = self.curr_sequence.write().await;
        let result = *curr_sequence;
        *curr_sequence = curr_sequence
            .checked_add(1)
            .expect("sequence must not overflow");

        result
    }
}

#[cfg(test)]
mod tests {
    use cosmrs::proto::cosmos::auth::v1beta1::{
        BaseAccount, QueryAccountRequest, QueryAccountResponse,
    };
    use cosmrs::tx::MessageExt;
    use mockall::predicate;
    use tokio::task::JoinSet;

    use super::*;
    use crate::cosmos::MockCosmosClient;
    use crate::types::random_cosmos_public_key;
    use crate::PREFIX;

    #[tokio::test]
    async fn new_cosmos_account_manager() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(|req| {
                Ok(QueryAccountResponse {
                    account: Some(
                        BaseAccount {
                            account_number: 42,
                            sequence: 10,
                            address: req.address,
                            pub_key: None,
                        }
                        .to_any()
                        .unwrap(),
                    ),
                })
            });

        let manager = AccountManager::new(mock_client, pub_key).await.unwrap();

        assert_eq!(manager.account_number(), 42);
        assert_eq!(*manager.curr_sequence.read().await, 10);
        assert_eq!(manager.address(), address);
        assert_eq!(manager.pub_key(), pub_key);
    }

    #[tokio::test]
    async fn curr_sequence() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(|req| {
                Ok(QueryAccountResponse {
                    account: Some(
                        BaseAccount {
                            account_number: 42,
                            sequence: 15,
                            address: req.address,
                            pub_key: None,
                        }
                        .to_any()
                        .unwrap(),
                    ),
                })
            });

        let manager = AccountManager::new(mock_client, pub_key).await.unwrap();

        assert_eq!(manager.curr_sequence().await, 15);
        assert_eq!(manager.curr_sequence().await, 15);
        assert_eq!(manager.curr_sequence().await, 15);
    }

    #[tokio::test]
    async fn curr_sequence_and_incr() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(|req| {
                Ok(QueryAccountResponse {
                    account: Some(
                        BaseAccount {
                            account_number: 42,
                            sequence: 15,
                            address: req.address,
                            pub_key: None,
                        }
                        .to_any()
                        .unwrap(),
                    ),
                })
            });

        let manager = AccountManager::new(mock_client, pub_key).await.unwrap();

        assert_eq!(manager.curr_sequence_and_incr().await, 15);
        assert_eq!(manager.curr_sequence_and_incr().await, 16);
        assert_eq!(manager.curr_sequence_and_incr().await, 17);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_curr_sequence_and_incr() {
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(|req| {
                Ok(QueryAccountResponse {
                    account: Some(
                        BaseAccount {
                            account_number: 42,
                            sequence: 10,
                            address: req.address,
                            pub_key: None,
                        }
                        .to_any()
                        .unwrap(),
                    ),
                })
            });
        mock_client.expect_clone().returning(MockCosmosClient::new);

        let manager = AccountManager::new(mock_client, pub_key).await.unwrap();

        let num_tasks = 50;
        let mut join_set = JoinSet::new();
        for _ in 0..num_tasks {
            let manager_clone = manager.clone();
            join_set.spawn(async move { manager_clone.curr_sequence_and_incr().await });
        }

        let mut results: Vec<_> = join_set.join_all().await.into_iter().collect();
        results.sort();

        for (i, seq) in results.iter().enumerate() {
            assert_eq!(*seq, 10 + i as u64);
        }

        assert_eq!(manager.curr_sequence().await, 10 + num_tasks as u64,);
    }
}
