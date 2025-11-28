use std::time::Duration;

use cosmrs::tendermint::chain::Id;
use cosmrs::Gas;
use serde::{Deserialize, Serialize};

use super::dec_coin::DecCoin;

/// Configuration for broadcasting transactions to the Axelar chain.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Config {
    /// Chain ID of the Axelar network (e.g., "axelar-dojo-1", "devnet-amplifier").
    pub chain_id: Id,

    /// Interval between attempts to fetch transaction confirmation status.
    ///
    /// After broadcasting a transaction, ampd polls for confirmation at this interval.
    #[serde(with = "humantime_serde")]
    pub tx_fetch_interval: Duration,

    /// Maximum number of retries when fetching transaction confirmation.
    ///
    /// Total confirmation timeout = `tx_fetch_interval * tx_fetch_max_retries`.
    pub tx_fetch_max_retries: u32,

    /// Gas adjustment multiplier applied to estimated gas.
    ///
    /// The estimated gas is multiplied by this factor to provide a safety margin.
    /// Higher values reduce out-of-gas failures but increase transaction costs.
    pub gas_adjustment: f64,

    /// Gas price for transactions (e.g., "0.00005uaxl").
    pub gas_price: DecCoin,

    /// Maximum total gas for a batch of messages in a single transaction.
    ///
    /// Messages are batched until this limit is reached, then broadcast together.
    pub batch_gas_limit: Gas,

    /// Maximum number of messages to queue before applying backpressure.
    ///
    /// When the queue reaches this capacity, new messages will block until space is available.
    pub queue_cap: usize,

    /// Minimum interval between broadcasting transactions.
    ///
    /// Limits how frequently transactions are sent to the chain.
    #[serde(with = "humantime_serde")]
    pub broadcast_interval: Duration,

    /// Maximum number of transaction confirmations to process concurrently.
    ///
    /// Higher values increase throughput for confirming many transactions
    /// but consume more resources.
    pub tx_confirmation_buffer_size: usize,

    /// Maximum capacity of the transaction confirmation queue.
    ///
    /// Determines how many transactions can be queued for confirmation before backpressure.
    /// Too small may cause confirmation requests to be dropped during traffic spikes.
    /// Too large may consume excessive memory if confirmations become backlogged.
    pub tx_confirmation_queue_cap: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: "axelar-dojo-1"
                .parse()
                .expect("default chain_id should be valid"),
            tx_fetch_interval: Duration::from_millis(500),
            tx_fetch_max_retries: 10,
            gas_adjustment: 1.2,
            gas_price: DecCoin::new(0.00005, "uaxl").expect("default gas price should be valid"),
            batch_gas_limit: 1000000,
            queue_cap: 1000,
            broadcast_interval: Duration::from_secs(1),
            tx_confirmation_buffer_size: 10,
            tx_confirmation_queue_cap: 1000,
        }
    }
}
