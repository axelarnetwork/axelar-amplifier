use std::time::Duration;

use cosmrs::tendermint::chain::Id;
use cosmrs::Gas;
use serde::{Deserialize, Serialize};

use super::dec_coin::DecCoin;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Config {
    pub chain_id: Id,
    #[serde(with = "humantime_serde")]
    pub tx_fetch_interval: Duration,
    pub tx_fetch_max_retries: u32,
    pub gas_adjustment: f64,
    pub gas_price: DecCoin,
    pub batch_gas_limit: Gas,
    pub queue_cap: usize,
    #[serde(with = "humantime_serde")]
    pub broadcast_interval: Duration,
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
            broadcast_interval: Duration::from_secs(5),
        }
    }
}
