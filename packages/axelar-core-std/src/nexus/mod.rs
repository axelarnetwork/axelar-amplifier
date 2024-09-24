use cosmwasm_std::CosmosMsg;
use error_stack::ResultExt;
use router_api::ChainName;

pub mod execute;
pub mod query;

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query the tx hash and nonce")]
    QueryTxHashAndNonce,

    #[error("failed to query is chain registered")]
    QueryIsChainRegistered,

    #[error("invalid message id {0}")]
    InvalidMessageId(String),
}

pub struct Client<'a> {
    inner: client::CosmosClient<'a, execute::Message>,
}

impl<'a> From<client::CosmosClient<'a, execute::Message>> for Client<'a> {
    fn from(inner: client::CosmosClient<'a, execute::Message>) -> Self {
        Client { inner }
    }
}

impl<'a> Client<'a> {
    pub fn tx_hash_and_nonce(&self) -> Result<query::TxHashAndNonceResponse> {
        self.inner
            .query(query::QueryMsg::TxHashAndNonce {})
            .change_context(Error::QueryTxHashAndNonce)
    }

    pub fn route_message(&self, msg: execute::Message) -> CosmosMsg<execute::Message> {
        self.inner.execute(msg)
    }

    pub fn is_chain_registered(
        &self,
        chain: &ChainName,
    ) -> Result<query::IsChainRegisteredResponse> {
        self.inner
            .query(query::QueryMsg::IsChainRegistered {
                chain: chain.to_string(),
            })
            .change_context(Error::QueryIsChainRegistered)
    }
}

#[cfg(test)]
mod test {
    use assert_ok::assert_ok;
    use cosmwasm_std::testing::{MockQuerier, MockQuerierCustomHandlerResult};
    use cosmwasm_std::{ContractResult, QuerierWrapper, SystemResult};
    use rand::RngCore;
    use serde::de::DeserializeOwned;
    use serde_json::json;

    use crate::nexus;
    use crate::query::AxelarQueryMsg;

    #[test]
    fn query_tx_hash_and_nonce() {
        let mut tx_hash = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut tx_hash);
        let nonce = rand::random();

        let querier: MockQuerier<AxelarQueryMsg> =
            MockQuerier::new(&[]).with_custom_handler(reply_with_tx_hash_and_nonce(tx_hash, nonce));

        let client: nexus::Client = client::CosmosClient::new(QuerierWrapper::new(&querier)).into();

        assert!(client
            .tx_hash_and_nonce()
            .is_ok_and(|response| { response.tx_hash == tx_hash && response.nonce == nonce }));
    }

    #[test]
    fn query_is_chain_registered() {
        let querier: MockQuerier<AxelarQueryMsg> =
            MockQuerier::new(&[]).with_custom_handler(|_| {
                SystemResult::Ok(ContractResult::Ok(
                    json!({
                        "is_registered": true,
                    })
                    .to_string()
                    .as_bytes()
                    .into(),
                ))
            });

        let client: nexus::Client = client::CosmosClient::new(QuerierWrapper::new(&querier)).into();

        assert!(
            assert_ok!(client.is_chain_registered(&"test-chain".parse().unwrap())).is_registered
        );
    }

    fn reply_with_tx_hash_and_nonce<C>(
        tx_hash: [u8; 32],
        nonce: u64,
    ) -> impl Fn(&C) -> MockQuerierCustomHandlerResult
    where
        C: DeserializeOwned,
    {
        move |_| {
            SystemResult::Ok(ContractResult::Ok(
                json!({
                    "tx_hash": tx_hash,
                    "nonce": nonce,
                })
                .to_string()
                .as_bytes()
                .into(),
            ))
        }
    }
}
