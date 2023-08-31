use crate::broadcaster::clients::AccountQueryClient;
use crate::types::TMAddress;
use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use cosmos_sdk_proto::traits::Message;
use error_stack::{FutureExt, IntoReport, Result, ResultExt};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to retrieve the account information for address {address}")]
    ResponseFailed { address: TMAddress },
    #[error("address {address} is unknown")]
    AccountNotFound { address: TMAddress },
    #[error("received response could not be decoded")]
    MalformedResponse,
}

pub async fn account<T>(mut client: T, address: &TMAddress) -> Result<BaseAccount, Error>
where
    T: AccountQueryClient,
{
    let response = client
        .account(QueryAccountRequest {
            address: address.to_string(),
        })
        .change_context_lazy(|| Error::ResponseFailed {
            address: address.clone(),
        })
        .await?;

    let account = response
        .account
        .ok_or_else(|| Error::AccountNotFound {
            address: address.clone(),
        })
        .into_report()
        .and_then(|account| {
            BaseAccount::decode(&account.value[..])
                .into_report()
                .change_context(Error::MalformedResponse)
                .attach_printable_lazy(|| format!("{{ value = {:?} }}", account.value))
        })?;

    Ok(account)
}

#[cfg(test)]
mod tests {
    use cosmos_sdk_proto::cosmos::auth::v1beta1::BaseAccount;
    use cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountResponse;
    use cosmos_sdk_proto::traits::MessageExt;
    use cosmrs::Any;
    use ecdsa::SigningKey;
    use error_stack::IntoReport;
    use rand::rngs::OsRng;
    use tokio::test;
    use tonic::Status;

    use crate::broadcaster::accounts::account;
    use crate::broadcaster::accounts::Error::*;
    use crate::broadcaster::clients::MockAccountQueryClient;
    use crate::types::PublicKey;
    use crate::types::TMAddress;

    #[test]
    async fn response_failed() {
        let mut client = MockAccountQueryClient::new();
        client
            .expect_account()
            .returning(|_| Err(Status::aborted("aborted")).into_report());

        let address = rand_tm_address();

        assert!(matches!(
            account(client, &address)
                .await
                .unwrap_err()
                .current_context(),
            ResponseFailed { address: _ }
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
            account(client, &address)
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
            account(client, &address)
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

        assert_eq!(account(client, &address).await.unwrap(), acc);
    }

    fn rand_tm_address() -> TMAddress {
        PublicKey::from(SigningKey::random(&mut OsRng).verifying_key())
            .account_id("axelar")
            .unwrap()
            .into()
    }
}
