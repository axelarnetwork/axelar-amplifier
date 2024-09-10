use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};

use crate::state::{Epoch, RewardsDistribution};

#[cw_serde]
pub struct VerifierDistribution {
    pub verifier_address: Addr,
    pub proxy_address: Option<Addr>,
    pub amount: Uint128,
}
pub enum Event {
    RewardsDistributed {
        rewards: Vec<VerifierDistribution>,
        epochs_processed: Vec<u64>,
        current_epoch: Epoch,
        can_distribute_more: bool,
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

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::RewardsDistributed {
                rewards,
                epochs_processed,
                current_epoch,
                can_distribute_more: more_epochs_to_distribute,
            } => cosmwasm_std::Event::new("rewards_distributed")
                .add_attribute(
                    "rewards",
                    serde_json::to_string(&rewards).expect("failed to serialize rewards"),
                )
                .add_attribute(
                    "epochs_processed",
                    serde_json::to_string(&epochs_processed)
                        .expect("failed to serialize epochs processed"),
                )
                .add_attribute(
                    "current_epoch",
                    serde_json::to_string(&current_epoch)
                        .expect("failed to serialize current epoch"),
                )
                .add_attribute("can_distribute_more", more_epochs_to_distribute.to_string()),
        }
    }
}
