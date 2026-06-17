use axelar_wasm_std::IntoEvent;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};

use crate::state::{Epoch, PoolId, RewardsDistribution};

#[cw_serde]
pub struct VerifierDistribution {
    pub verifier_address: Addr,
    pub proxy_address: Option<Addr>,
    pub amount: Uint128,
}

#[derive(IntoEvent)]
pub enum Event {
    RewardsDistributed {
        rewards: Vec<VerifierDistribution>,
        epochs_processed: Vec<u64>,
        current_epoch: Epoch,
        can_distribute_more: bool,
    },
    ProxySendFailed {
        pool_id: PoolId,
        verifier_address: Addr,
        proxy_address: Addr,
        amount: Uint128,
    },
    VerifierSendFailed {
        pool_id: PoolId,
        verifier_address: Addr,
        proxy_address: Option<Addr>,
        amount: Uint128,
    },
}

impl From<RewardsDistribution> for Event {
    fn from(value: RewardsDistribution) -> Self {
        Event::RewardsDistributed {
            rewards: value
                .rewards
                .into_iter()
                .map(|(v, amount)| VerifierDistribution {
                    verifier_address: v.verifier_address,
                    proxy_address: v.proxy_address,
                    amount,
                })
                .collect(),
            epochs_processed: value.epochs_processed,
            current_epoch: value.current_epoch,
            can_distribute_more: value.can_distribute_more,
        }
    }
}
