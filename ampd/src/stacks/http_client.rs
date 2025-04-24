use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use futures::future::join_all;
use hex::ToHex;
use serde::Deserialize;
use thiserror::Error;

use crate::types::Hash;
use crate::url::Url;

const TRANSACTION: &str = "extended/v1/tx/0x";
const LATEST_BLOCK: &str = "extended/v2/blocks/latest";

const STATUS_SUCCESS: &str = "success";

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create client")]
    Client,
    #[error("invalid tx hash")]
    TxHash,
}

#[derive(Debug, Deserialize, Default)]
pub struct ContractLogValue {
    pub hex: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct ContractLog {
    pub contract_id: String,
    pub topic: String,
    pub value: ContractLogValue,
}

#[derive(Debug, Deserialize, Default)]
pub struct TransactionEvents {
    pub event_index: u64,
    pub contract_log: Option<ContractLog>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Transaction {
    pub tx_id: Hash,
    pub tx_status: String, // 'success'
    pub events: Vec<TransactionEvents>,
    pub block_height: u64,
}

#[derive(Debug, Deserialize, Default)]
pub struct Block {
    pub height: u64,
}

#[cfg_attr(test, faux::create)]
pub struct Client {
    api_url: String,
    client: reqwest::Client,
}

#[cfg_attr(test, faux::methods)]
impl Client {
    pub fn new_http(api_url: Url) -> Self {
        Client {
            api_url: api_url.to_string().trim_end_matches('/').into(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn finalized_transactions(
        &self,
        tx_hashes: HashSet<Hash>,
        finalized_block_height: u64,
    ) -> HashMap<Hash, Transaction> {
        let tx_hashes = Vec::from_iter(tx_hashes);

        let txs = join_all(
            tx_hashes
                .iter()
                .map(|tx_hash| self.valid_transaction(tx_hash, finalized_block_height)),
        )
        .await;

        tx_hashes
            .into_iter()
            .zip(txs)
            .filter_map(|(hash, tx)| {
                tx.as_ref()?;

                Some((hash, tx.unwrap()))
            })
            .collect()
    }

    pub async fn valid_transaction(
        &self,
        tx_hash: &Hash,
        finalized_block_height: u64,
    ) -> Option<Transaction> {
        self.transaction(tx_hash.encode_hex::<String>().as_str())
            .await
            .ok()
            .filter(|tx| Self::is_valid_transaction(tx, finalized_block_height))
    }

    pub async fn latest_block(&self) -> Result<Block, Error> {
        let endpoint = LATEST_BLOCK.to_string();

        let endpoint = self.endpoint(endpoint.as_str());

        self.client
            .get(endpoint)
            .send()
            .await
            .map_err(|_| Error::Client)?
            .json::<Block>()
            .await
            .map_err(|_| Error::Client)
    }

    async fn transaction(&self, tx_id: &str) -> Result<Transaction, Error> {
        let endpoint = TRANSACTION.to_string() + tx_id;

        let endpoint = self.endpoint(endpoint.as_str());

        self.client
            .get(endpoint)
            .send()
            .await
            .map_err(|_| Error::TxHash)?
            .json::<Transaction>()
            .await
            .map_err(|_| Error::Client)
    }

    fn endpoint(&self, endpoint: &str) -> String {
        format!("{}/{}", self.api_url, endpoint)
    }

    fn is_valid_transaction(tx: &Transaction, finalized_block_height: u64) -> bool {
        tx.tx_status == *STATUS_SUCCESS && tx.block_height <= finalized_block_height
    }
}

#[cfg(test)]
mod tests {
    use super::{Block, Client, Transaction};

    #[test]
    fn parse_transaction() {
        let data = r#"
{
    "tx_id": "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf",
    "nonce": 2,
    "fee_rate": "943",
    "sender_address": "SP3F7B2PGN7TVMTNBS1HBJBEC6M64DMCY944MXDD0",
    "sponsored": false,
    "post_condition_mode": "deny",
    "post_conditions": [],
    "anchor_mode": "any",
    "block_hash": "0x9248a412fc98e245820160aba1f89defefe5380af920bff73bc6617207284aa9",
    "block_height": 168868,
    "block_time": 1728309360,
    "block_time_iso": "2024-10-07T13:56:00.000Z",
    "burn_block_time": 1728309301,
    "burn_block_height": 864594,
    "burn_block_time_iso": "2024-10-07T13:55:01.000Z",
    "parent_burn_block_time": 1728308843,
    "parent_burn_block_time_iso": "2024-10-07T13:47:23.000Z",
    "canonical": true,
    "tx_index": 85,
    "tx_status": "success",
    "tx_result": {
        "hex": "0x0703",
        "repr": "(ok true)"
    },
    "event_count": 1,
    "parent_block_hash": "0x1cbb43f502524bfa0edbb16b5f2a98350de6d8041c93dd54eab35347a90f6a68",
    "is_unanchored": false,
    "microblock_hash": "0x",
    "microblock_sequence": 2147483647,
    "microblock_canonical": true,
    "execution_cost_read_count": 6,
    "execution_cost_read_length": 13939,
    "execution_cost_runtime": 46110,
    "execution_cost_write_count": 1,
    "execution_cost_write_length": 125,
    "events": [
        {
            "event_index": 0,
            "event_type": "smart_contract_log",
            "tx_id": "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf",
            "contract_log": {
                "contract_id": "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.leo-cats",
                "topic": "print",
                "value": {
                    "hex": "0x0c0000000501610d0000000c6c6973742d696e2d757374780a636f6d6d697373696f6e06162bcf9762d5b90bc36dc1b4759b1727690f92ddd31367616d6d612d636f6d6d697373696f6e2d76310269640100000000000000000000000000000d7105707269636501000000000000000000000000004e89b307726f79616c74790100000000000000000000000000000000",
                    "repr": "(tuple (a \"list-in-ustx\") (commission 'SPNWZ5V2TPWGQGVDR6T7B6RQ4XMGZ4PXTEE0VQ0S.gamma-commission-v1) (id u3441) (price u5147059) (royalty u0))"
                }
            }
        },
        {
            "event_index": 1,
            "event_type": "fungible_token_asset",
            "tx_id": "0xea34df6d263a274ec852b04f3d9bc13b989811f263c58e02293504c3e66164fd",
            "asset": {
                "asset_event_type": "transfer",
                "asset_id": "SP3K8BC0PPEVCV7NZ6QSRWPQ2JE9E5B6N3PA0KBR9.brc20-db20::brc20-db20",
                "sender": "SPP2B792YYNWTM5W8N3TBJT51745K8HPSCP9EFTT",
                "recipient": "SP38AN2F75Y4AP8ZVA7402XPK77F82TBQX05R8EH6",
                "amount": "1548865732"
            }
        }
    ],
    "tx_type": "contract_call",
    "contract_call": {
        "contract_id": "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.leo-cats",
        "function_name": "list-in-ustx",
        "function_signature": "(define-public (list-in-ustx (id uint) (price uint) (comm-trait trait_reference)))",
        "function_args": [
            {
                "hex": "0x0100000000000000000000000000000d71",
                "repr": "u3441",
                "name": "id",
                "type": "uint"
            }
        ]
    }
}
        "#;

        let transaction = serde_json::from_str::<Transaction>(data).unwrap();
        assert_eq!(
            transaction.tx_id,
            "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
                .parse()
                .unwrap()
        );
        assert_eq!(transaction.tx_status, "success");
        assert_eq!(transaction.events.len(), 2);
        assert_eq!(transaction.block_height, 168868);

        let event = transaction.events.get(0).unwrap();

        assert_eq!(event.event_index, 0);
        assert!(event.contract_log.is_some());

        let contract_log = event.contract_log.as_ref().unwrap();

        assert_eq!(
            contract_log.contract_id,
            "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.leo-cats"
        );
        assert_eq!(contract_log.topic, "print");
        assert_eq!(contract_log.value.hex, "0x0c0000000501610d0000000c6c6973742d696e2d757374780a636f6d6d697373696f6e06162bcf9762d5b90bc36dc1b4759b1727690f92ddd31367616d6d612d636f6d6d697373696f6e2d76310269640100000000000000000000000000000d7105707269636501000000000000000000000000004e89b307726f79616c74790100000000000000000000000000000000");

        let token_event = transaction.events.get(1).unwrap();

        assert_eq!(token_event.event_index, 1);
        assert!(token_event.contract_log.is_none());
    }

    #[test]
    fn parse_block() {
        let data = r#"
{
    "canonical": true,
    "height": 88985,
    "hash": "0x894846ccdee69ffd2ad13dc8d929a8e5736f15dd19e40e7f16a859fde3fc1842",
    "block_time": 1737640361,
    "block_time_iso": "2025-01-23T13:52:41.000Z",
    "tenure_height": 6675,
    "index_block_hash": "0xce5225b888af1f5f16d385b069d945ff88d1a9af1598ee7acc04d8f4a54b03b2",
    "parent_block_hash": "0x001d520837162c69ff91ad3ae11fba242d69f5d184665558ecf7f02ad87aeccc",
    "parent_index_block_hash": "0x7134f2499b7d9fc6bfe384ac18daa905cd845dc53b93ab5c7922494272a7a9ca",
    "burn_block_time": 1737640346,
    "burn_block_time_iso": "2025-01-23T13:52:26.000Z",
    "burn_block_hash": "0x3bbaaa8b360ea9be2594e8f3710d8be41cc13cf7b228f54a0733cbaa552d2f47",
    "burn_block_height": 9037,
    "miner_txid": "0x188f36850652abb30d315b777d3274f0a0440466cddd331af9be67b4d678a698",
    "tx_count": 1,
    "execution_cost_read_count": 0,
    "execution_cost_read_length": 0,
    "execution_cost_runtime": 0,
    "execution_cost_write_count": 0,
    "execution_cost_write_length": 0
}
        "#;

        let block = serde_json::from_str::<Block>(data).unwrap();
        assert_eq!(block.height, 88985);
    }

    #[test]
    fn should_not_be_valid_transaction_invalid_status() {
        let tx = Transaction {
            tx_status: "pending".into(),
            ..Transaction::default()
        };

        assert!(!Client::is_valid_transaction(&tx, 1));
    }

    #[test]
    fn should_not_be_valid_transaction_invalid_block_height() {
        let tx = Transaction {
            tx_status: "success".into(),
            block_height: 2,
            ..Transaction::default()
        };

        assert!(!Client::is_valid_transaction(&tx, 1));
    }

    #[test]
    fn should_be_valid_transaction() {
        let tx = Transaction {
            tx_status: "success".into(),
            block_height: 1,
            ..Transaction::default()
        };

        assert!(Client::is_valid_transaction(&tx, 1));

        let tx = Transaction {
            tx_status: "success".into(),
            block_height: 1,
            ..Transaction::default()
        };

        assert!(Client::is_valid_transaction(&tx, 2));
    }
}
