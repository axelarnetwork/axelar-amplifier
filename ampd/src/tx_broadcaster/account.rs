use std::cmp;
use std::sync::Arc;

use error_stack::{report, ResultExt};
use mockall::automock;
use report::ResultCompatExt;
use tokio::sync::{Mutex, MutexGuard};

use super::{Error, Result};
use crate::types::{CosmosPublicKey, TMAddress};
use crate::{cosmos, PREFIX};

#[automock]
pub trait AccountManager {
    fn pub_key(&self) -> CosmosPublicKey;
    fn address(&self) -> TMAddress;
    fn account_number(&self) -> u64;
    async fn curr_sequence(&mut self) -> Result<u64>;
    async fn curr_sequence_and_incr(&mut self) -> Result<u64>;
}

#[derive(Clone)]
pub struct CosmosAccountManager<T>
where
    T: cosmos::CosmosClient + Clone,
{
    client: T,
    pub_key: CosmosPublicKey,
    address: TMAddress,
    account_number: u64,
    curr_sequence: Arc<Mutex<u64>>,
}

impl<T> CosmosAccountManager<T>
where
    T: cosmos::CosmosClient + Clone,
{
    pub async fn new(mut client: T, pub_key: CosmosPublicKey) -> Result<Self> {
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
                curr_sequence: Arc::new(Mutex::new(account.sequence)),
            })
            .change_context(Error::QueryAccount)
    }

    async fn set_curr_sequence(&mut self) -> Result<MutexGuard<u64>> {
        let mut curr_sequence = self.curr_sequence.lock().await;
        *curr_sequence = cosmos::account(&mut self.client, &self.address)
            .await
            .map(|account| cmp::max(account.sequence, *curr_sequence))
            .change_context(Error::QueryAccount)?;

        Ok(curr_sequence)
    }
}

impl<T> AccountManager for CosmosAccountManager<T>
where
    T: cosmos::CosmosClient + Clone,
{
    fn pub_key(&self) -> CosmosPublicKey {
        self.pub_key.clone()
    }

    fn address(&self) -> TMAddress {
        self.address.clone()
    }

    fn account_number(&self) -> u64 {
        self.account_number
    }

    async fn curr_sequence(&mut self) -> Result<u64> {
        let curr_sequence = self.set_curr_sequence().await?;

        Ok(*curr_sequence)
    }

    async fn curr_sequence_and_incr(&mut self) -> Result<u64> {
        let mut curr_sequence = self.set_curr_sequence().await?;
        let result = *curr_sequence;

        *curr_sequence = curr_sequence
            .checked_add(1)
            .ok_or(report!(Error::IntegerOverflow))?;

        Ok(result)
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
        let mut mock_client = MockCosmosClient::new();
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();

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

        let manager = CosmosAccountManager::new(mock_client, pub_key.clone())
            .await
            .unwrap();

        assert_eq!(manager.account_number(), 42);
        assert_eq!(*manager.curr_sequence.lock().await, 10);
        assert_eq!(manager.address(), address);
        assert_eq!(manager.pub_key(), pub_key);
    }

    #[tokio::test]
    async fn curr_sequence() {
        let mut mock_client = MockCosmosClient::new();
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();

        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .times(4)
            .returning(|req| {
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

        let mut manager = CosmosAccountManager::new(mock_client, pub_key)
            .await
            .unwrap();

        assert_eq!(manager.curr_sequence().await.unwrap(), 15);
        assert_eq!(manager.curr_sequence().await.unwrap(), 15);
        assert_eq!(manager.curr_sequence().await.unwrap(), 15);
    }

    #[tokio::test]
    async fn curr_sequence_and_incr() {
        let mut mock_client = MockCosmosClient::new();
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();

        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .times(4)
            .returning(|req| {
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

        let mut manager = CosmosAccountManager::new(mock_client, pub_key)
            .await
            .unwrap();

        assert_eq!(manager.curr_sequence_and_incr().await.unwrap(), 15);
        assert_eq!(manager.curr_sequence_and_incr().await.unwrap(), 16);
        assert_eq!(manager.curr_sequence_and_incr().await.unwrap(), 17);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_curr_sequence_and_incr() {
        let mut mock_client = MockCosmosClient::new();
        let pub_key = random_cosmos_public_key();
        let address: TMAddress = pub_key.account_id(PREFIX).unwrap().into();
        let address_clone = address.clone();

        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .returning(|req| {
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
        mock_client.expect_clone().returning(move || {
            let mut mock_client = MockCosmosClient::new();
            mock_client
                .expect_account()
                .with(predicate::eq(QueryAccountRequest {
                    address: address_clone.to_string(),
                }))
                .returning(|req| {
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

            mock_client
        });

        let mut manager = CosmosAccountManager::new(mock_client, pub_key)
            .await
            .unwrap();

        let num_tasks = 50;
        let mut join_set = JoinSet::new();
        for _ in 0..num_tasks {
            let mut manager_clone = manager.clone();
            join_set.spawn(async move { manager_clone.curr_sequence_and_incr().await });
        }

        let mut results: Vec<_> = join_set
            .join_all()
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect();
        results.sort();

        for (i, seq) in results.iter().enumerate() {
            assert_eq!(*seq, 10 + i as u64);
        }

        assert_eq!(
            manager.curr_sequence().await.unwrap(),
            10 + num_tasks as u64,
        );
    }
}
