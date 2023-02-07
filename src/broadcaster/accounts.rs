use crate::broadcaster::clients::AccountQueryClient;
use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use cosmos_sdk_proto::traits::Message;
use error_stack::{FutureExt, IntoReport, Result, ResultExt};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to retrieve the account information for address {address}")]
    ResponseFailed { address: String },
    #[error("address {address} is unknown")]
    AccountNotFound { address: String },
    #[error("received response could not be decoded")]
    MalformedResponse,
}

pub async fn account<T>(mut client: T, address: String) -> Result<BaseAccount, Error>
where
    T: AccountQueryClient,
{
    let response = client
        .account(QueryAccountRequest {
            address: address.clone(),
        })
        .change_context_lazy(|| Error::ResponseFailed {
            address: address.clone(),
        })
        .await?;

    let account = response
        .account
        .ok_or(Error::AccountNotFound {
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
    use crate::broadcaster::accounts::account;
    use crate::broadcaster::accounts::Error::*;

    use crate::broadcaster::clients::MockAccountQueryClient;
    use cosmos_sdk_proto::cosmos::auth::v1beta1::BaseAccount;
    use cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountResponse;
    use cosmos_sdk_proto::traits::MessageExt;
    use cosmrs::Any;
    use error_stack::IntoReport;
    use tokio::test;
    use tonic::Status;

    #[test]
    async fn response_failed() {
        let mut client = MockAccountQueryClient::new();
        client
            .expect_account()
            .returning(|_| Err(Status::aborted("aborted")).into_report());

        let address = String::from("some_address");

        assert!(matches!(
            account(client, address).await.unwrap_err().current_context(),
            ResponseFailed { address: _ }
        ));
    }

    #[test]
    async fn account_not_found() {
        let mut client = MockAccountQueryClient::new();
        client
            .expect_account()
            .returning(|_| Ok(QueryAccountResponse { account: None }));

        let address = String::from("some_address");

        assert!(matches!(
            account(client, address).await.unwrap_err().current_context(),
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

        let address = String::from("some_address");

        assert!(matches!(
            account(client, address).await.unwrap_err().current_context(),
            MalformedResponse
        ));
    }

    #[test]
    async fn get_existing_account() {
        let address = String::from("some_address");
        let acc = BaseAccount {
            address: address.clone(),
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

        assert_eq!(account(client, address.clone()).await.unwrap(), acc);
    }
}
