use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};
use cw_storage_plus::{Item, VecDeque};
use sha3::{Digest, Keccak256};

#[cw_serde]
pub struct ServiceInfo {
    pub router_contract: Addr,
    pub destination_chain_id: Uint256,
    pub destination_chain_name: String,
}

#[cw_serde]
pub enum BatchedCommandsStatus {
    Signing,
    Aborted,
    Signed,
}

#[cw_serde]
pub struct CommandBatch {
    pub id: [u8; 32],
    pub commands_ids: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub status: BatchedCommandsStatus,
}

impl CommandBatch {
    pub fn new(block_height: u64, commands_ids: Vec<[u8; 32]>, data: Vec<u8>) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(block_height.to_be_bytes());
        hasher.update(&data);
        let id = hasher
            .finalize()
            .as_slice()
            .try_into()
            .expect("Wrong length");

        Self {
            id,
            commands_ids,
            data,
            status: BatchedCommandsStatus::Signing,
        }
    }

    pub fn command_ids_hex_string(&self) -> String {
        self.commands_ids
            .iter()
            .fold(String::new(), |mut accum, command_id| {
                let hex_string = hex::encode(command_id.to_vec());
                accum.push_str(&hex_string);
                accum
            })
    }
}

pub const SERVICE_INFO: Item<ServiceInfo> = Item::new("service");
pub const COMMANDS_BATCH_QUEUE: VecDeque<CommandBatch> = VecDeque::new("command_batchs");
