// use aleo_types::transaction::Transaction;
// use aleo_types::transition::Transition;
use async_trait::async_trait;
use error_stack::{Result, ResultExt};
use mockall::automock;
use snarkvm::prelude::Network;

use crate::aleo::error::Error;
use crate::url::Url;

#[automock]
#[async_trait]
pub trait ClientTrait<N: Network>: Send {
    async fn get_transaction(
        &self,
        transaction_id: &N::TransactionID,
    ) -> Result<aleo_utils::block_processor::Transaction, Error>;

    async fn find_transaction(&self, transition_id: &N::TransitionID) -> Result<String, Error>;
}

#[derive(Clone)]
pub struct Client {
    client: reqwest::Client,
    base_url: Url,
    network: String,
}

impl Client {
    pub fn new(client: reqwest::Client, base_url: Url, network: String) -> Self {
        Self {
            client,
            base_url,
            network,
        }
    }
}

#[async_trait]
impl<N: Network> ClientTrait<N> for Client {
    #[tracing::instrument(skip(self), fields(%transaction_id))]
    async fn get_transaction(
        &self,
        transaction_id: &N::TransactionID,
    ) -> Result<aleo_utils::block_processor::Transaction, Error> {
        const ENDPOINT: &str = "transaction";
        let url = format!(
            "{}{}/{ENDPOINT}/{}",
            self.base_url, self.network, &transaction_id
        );

        tracing::debug!(%url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(Error::from)
            .attach_printable_lazy(|| format!("target url: '{url:?}'"))?;

        let transaction: aleo_utils::block_processor::Transaction =
            serde_json::from_str(&response.text().await.map_err(Error::from)?)
                .map_err(Error::from)?;

        Ok(transaction)
    }

    #[tracing::instrument(skip(self), fields(%transition_id))]
    async fn find_transaction(&self, transition_id: &N::TransitionID) -> Result<String, Error> {
        const ENDPOINT: &str = "find/transactionID";
        let url = format!(
            "{}{}/{ENDPOINT}/{}",
            self.base_url, self.network, &transition_id
        );

        tracing::debug!(%url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(Error::from)
            .attach_printable_lazy(|| format!("target url: '{url:?}'"))?
            .text()
            .await
            .map_err(Error::from)?;

        Ok(response)
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use snarkvm::prelude::ProgramID;

    use super::*;
    use crate::aleo::ReceiptBuilder;

    type CurrentNetwork = snarkvm::prelude::TestnetV0;

    pub fn mock_client<N: Network>(transaction_id: &str, transaction: &str) -> MockClientTrait<N> {
        let mut mock_client = MockClientTrait::new();

        let mut expected_transitions: HashMap<
            N::TransactionID,
            aleo_utils::block_processor::Transaction,
        > = HashMap::new();

        let snark_tansaction: aleo_utils::block_processor::Transaction =
            serde_json::from_str(transaction).unwrap();
        let transaction = N::TransactionID::from_str(transaction_id)
            .map_err(|_| ())
            .expect("Failed to parse transaction ID");
        expected_transitions.insert(transaction, snark_tansaction);

        mock_client
            .expect_get_transaction()
            .returning(move |transaction| {
                Ok(expected_transitions
                    .get(transaction)
                    .expect("Failed to find transaction")
                    .clone())
            });

        mock_client
            .expect_find_transaction()
            .returning(move |_| Ok(transaction.to_string()));

        mock_client
    }

    #[tokio::test]
    async fn aleo_verify_msg_transfer() {
        let transaction_id = "at1pmfmnh50055ml9h4p4895uwumnts92a5v8syw26ydkkvm5vdlqrqqmw4m3";
        let client = mock_client(
            transaction_id,
            include_str!(
                "../tests/at1pmfmnh50055ml9h4p4895uwumnts92a5v8syw26ydkkvm5vdlqrqqmw4m3.json"
            ),
        );
        let transision_id = "au10yyqs2ucva9phs55qycajtssmu43pz3thl5zvyrqjg62jak4zvxq2spwhp";
        let transition =
            <CurrentNetwork as snarkvm::prelude::Network>::TransitionID::from_str(transision_id)
                .map_err(|_| ())
                .expect("Failed to parse transition ID");
        let gateway_contract =
            ProgramID::from_str("gateway_frontend.aleo").expect("Failed to parse program ID");

        ReceiptBuilder::<CurrentNetwork, _, _>::new(&client, &gateway_contract)
            .unwrap()
            .get_transaction_id(&transition)
            .await
            .expect("Failed to get transaction ID")
            .get_transaction()
            .await
            .expect("Failed to get transaction")
            .get_transition()
            .expect("Failed to get transition")
            .check_call_contract()
            .expect("Failed to check call contract");
    }

    #[tokio::test]
    async fn aleo_verify_msg_transfer_2() {
        let transaction_id = "at188kfg7uxqc0rpzlq66y7mp293a5vauqr5jdlg3a7v9tk9wpsavgqe7ww5l";
        let client = mock_client(
            transaction_id,
            include_str!(
                "../tests/at188kfg7uxqc0rpzlq66y7mp293a5vauqr5jdlg3a7v9tk9wpsavgqe7ww5l.json"
            ),
        );
        let transision_id = "au130u5y9kvf7rf6663tlamkaq9549gzddkkf7cd2997aaedglxdcqsl6pxl4";
        let transition =
            <CurrentNetwork as snarkvm::prelude::Network>::TransitionID::from_str(transision_id)
                .map_err(|_| ())
                .expect("Failed to parse transition ID");
        let gateway_contract =
            ProgramID::from_str("gateway_frontend.aleo").expect("Failed to parse program ID");

        ReceiptBuilder::<CurrentNetwork, _, _>::new(&client, &gateway_contract)
            .expect("Failed to create receipt builder")
            .get_transaction_id(&transition)
            .await
            .expect("Failed to get transaction ID")
            .get_transaction()
            .await
            .expect("Failed to get transaction")
            .get_transition()
            .expect("Failed to get transition")
            .check_call_contract()
            .expect("Failed to check call contract");
    }
}
