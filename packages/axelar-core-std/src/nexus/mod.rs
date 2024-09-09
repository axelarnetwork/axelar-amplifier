use cosmwasm_std::CosmosMsg;
use error_stack::ResultExt;

pub mod execute;
pub(crate) mod query;

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query the tx hash and nonce")]
    QueryTxHashAndNonce,

    #[error("invalid message id {0}")]
    InvalidMessageId(String),
}

pub struct Client<'a> {
    inner: client::Client<'a, execute::Message>,
}

impl<'a> From<client::Client<'a, execute::Message>> for Client<'a> {
    fn from(inner: client::Client<'a, execute::Message>) -> Self {
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
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::MockQuerier;
    use cosmwasm_std::{ContractResult, QuerierWrapper, SystemResult};
    use serde_json::json;

    use crate::nexus;
    use crate::query::QueryMsg;

    #[test]
    fn query_tx_hash_and_nonce() {
        let tx_hash = "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1";
        let nonce = 150u64;
        let querier: MockQuerier<QueryMsg> =
            MockQuerier::new(&[]).with_custom_handler(move |query| {
                assert_eq!(
                    *query,
                    QueryMsg::Nexus(nexus::query::QueryMsg::TxHashAndNonce {})
                );

                SystemResult::Ok(ContractResult::Ok(
                    json!({
                        "tx_hash": hex::decode(tx_hash).unwrap(),
                        "nonce": nonce,
                    })
                    .to_string()
                    .as_bytes()
                    .into(),
                ))
            });

        let client: nexus::Client = client::Client::new(QuerierWrapper::new(&querier)).into();

        assert!(client.tx_hash_and_nonce().is_ok_and(|response| {
            response.tx_hash == *hex::decode(tx_hash).unwrap() && response.nonce == nonce
        }));
    }
}
