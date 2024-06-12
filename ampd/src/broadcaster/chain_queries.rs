use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use cosmrs::proto::cosmos::bank::v1beta1::QueryBalanceRequest;
use cosmrs::proto::traits::Message;
use cosmrs::{Coin, Denom};
use error_stack::{report, IntoReportCompat, Result, ResultExt};
use thiserror::Error;

use crate::broadcaster::clients::{AccountQueryClient, BalanceQueryClient};
use crate::types::TMAddress;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to receive '{query_name}' query response")]
    ResponseFailed { query_name: String },
    #[error("address {address} is unknown")]
    AccountNotFound { address: TMAddress },
    #[error("balance not found")]
    BalanceNotFound,
    #[error("received response could not be decoded")]
    MalformedResponse,
}

pub async fn account<T>(client: &mut T, address: &TMAddress) -> Result<BaseAccount, Error>
where
    T: AccountQueryClient,
{
    let response = client
        .account(QueryAccountRequest {
            address: address.to_string(),
        })
        .await
        .map_err(|report| match report.current_context().code() {
            tonic::Code::NotFound => {
                report.attach_printable("to proceed, please ensure the account is funded")
            }
            _ => report,
        })
        .change_context_lazy(|| Error::ResponseFailed {
            query_name: "account".to_string(),
        })?;

    let account = response
        .account
        .ok_or_else(|| {
            Error::AccountNotFound {
                address: address.clone(),
            }
            .into()
        })
        .and_then(|account| {
            BaseAccount::decode(&account.value[..])
                .change_context(Error::MalformedResponse)
                .attach_printable_lazy(|| format!("{{ value = {:?} }}", account.value))
        })?;

    Ok(account)
}

pub async fn balance(
    client: &mut impl BalanceQueryClient,
    address: TMAddress,
    denom: Denom,
) -> Result<Coin, Error> {
    let x = client
        .balance(QueryBalanceRequest {
            address: address.to_string(),
            denom: denom.to_string(),
        })
        .await
        .change_context(Error::ResponseFailed {
            query_name: "balance".to_string(),
        })?
        .balance;

    x.ok_or(report!(Error::BalanceNotFound)).and_then(|coin| {
        Coin::try_from(coin)
            .into_report()
            .map_err(|report| report.change_context(Error::MalformedResponse))
    })
}

#[cfg(test)]
mod tests {
    use cosmrs::proto::cosmos::auth::v1beta1::BaseAccount;
    use cosmrs::proto::cosmos::auth::v1beta1::QueryAccountResponse;
    use cosmrs::proto::traits::MessageExt;
    use cosmrs::Any;
    use ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use tokio::test;
    use tonic::Status;

    use crate::broadcaster::chain_queries::account;
    use crate::broadcaster::chain_queries::Error::*;
    use crate::broadcaster::clients::MockAccountQueryClient;
    use crate::types::PublicKey;
    use crate::types::TMAddress;

    #[test]
    async fn response_failed() {
        let mut client = MockAccountQueryClient::new();
        client
            .expect_account()
            .returning(|_| Err(Status::aborted("aborted").into()));

        let address = rand_tm_address();

        assert!(matches!(
            account(&mut client, &address)
                .await
                .unwrap_err()
                .current_context(),
            ResponseFailed { query_name: _ }
        ));
    }

    #[test]
    async fn account_not_found() {
        let mut client = MockAccountQueryClient::new();
        client
            .expect_account()
            .returning(|_| Ok(QueryAccountResponse { account: None }));

        let address = rand_tm_address();

        assert!(matches!(
            account(&mut client, &address)
                .await
                .unwrap_err()
                .current_context(),
            AccountNotFound { address: _ }
        ));
    }

    #[test]
    async fn malformed_response() {
        let mut client = MockAccountQueryClient::new();
        client.expect_account().returning(|_| {
            Ok(QueryAccountResponse {
                account: Some(Any {
                    type_url: "wrong_type".to_string(),
                    value: vec![1, 2, 3, 4, 5],
                }),
            })
        });

        let address = rand_tm_address();

        assert!(matches!(
            account(&mut client, &address)
                .await
                .unwrap_err()
                .current_context(),
            MalformedResponse
        ));
    }

    #[test]
    async fn get_existing_account() {
        let address = rand_tm_address();
        let acc = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 7,
            sequence: 20,
        };
        let any = acc.clone().to_any().unwrap();

        let mut client = MockAccountQueryClient::new();
        client.expect_account().returning(move |_| {
            Ok(QueryAccountResponse {
                account: Some(any.to_owned()),
            })
        });

        assert_eq!(account(&mut client, &address).await.unwrap(), acc);
    }

    fn rand_tm_address() -> TMAddress {
        PublicKey::from(SigningKey::random(&mut OsRng).verifying_key())
            .account_id("axelar")
            .unwrap()
            .into()
    }
}
