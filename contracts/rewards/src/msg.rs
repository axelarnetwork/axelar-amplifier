use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {
    governance_address: String,
    rewards_denom: String,
    params: RewardsParams,
}

#[cw_serde]
pub struct RewardsParams {
        // How often rewards are calculated, specified in number of blocks. Participation is calculated over this window. So if epoch is 500
        // blocks, validators are rewarded for their participation within each 500 block window. 
        epoch_duration: nonempty::Uint64, 
        // Total length of time over which rewards in a pool are distributed, specified in number of blocks. For example, if pool_duration is
        // 1 million blocks, and epoch_duration is 500 blocks, every 500 blocks, 1 million / 500 ( = 5,000) tokens are distributed to participating
        // validators. The tokens to be distributed are split equally amongst the participating validators
        pool_duration: nonempty::Uint64,
        // Participation threshold validators must meet to receive rewards in a given epoch, specified as a fraction between 0 and 1. Validators
        // must participate in at least this fraction of all events in a given epoch to receive rewards. So, if participation_threshold is 9/10,
        // and there are 100 events in a given epoch, validators must have participated in at least 90 events to receive rewards.
        // Participation is reset at the beginning of each epoch, so participation in previous epochs does not affect rewards for future epochs.
        participation_threshold: nonempty::Uint64,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Called each time a new event is started, for which validators are rewarded for participating
    StartValidatorEvent {
        event_id: String,
    },
    // Log a specific validator as participating in a specific event
    ValidatorParticipated {
        event_id: String,
        validator_address: String,
    },
    // Process rewards for the most recent epoch, if not yet processed, and send the required number of tokens to each validator
    ProcessRewards {
        // Address of contract for which to process rewards.
        // For example, address of a voting verifier instance.
        contract_address: String,
    },
    // Increase the number of AXL tokens 
    AddRewards {
        // Address of contract for which to reward participation.
        // For example, address of a voting verifier instance. Validators who vote 
        contract_address: String,
    },
    // callable only by governance. overwrites currently stored params
    ModifyParams {
        params: RewardsParams
    }
}

#[cw_serde]
pub enum QueryMsg {}
