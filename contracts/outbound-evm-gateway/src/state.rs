use auth_multisig::AuthMultisig;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};
use cw_storage_plus::{Item, Map};
use sha3::{Digest, Keccak256};

#[cw_serde]
pub struct ServiceInfo {
    pub service_registry: Addr,
    pub name: String,
    pub reward_pool: Addr,
    pub router_contract: Addr,
}

#[cw_serde]
pub struct OutboundSettings {
    pub destination_chain_id: Uint256, // TODO: rename to outbound?
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
    pub sig_hash: [u8; 32],
    pub status: BatchedCommandsStatus,
}

impl CommandBatch {
    pub fn new(block_height: u64, commands_ids: Vec<[u8; 32]>, data: Vec<u8>) -> Self {
        let mut id_hasher = Keccak256::new();
        id_hasher.update(block_height.to_be_bytes());
        id_hasher.update(&data);
        let id = id_hasher
            .finalize()
            .as_slice()
            .try_into()
            .expect("Wrong length");

        let data_hash: [u8; 32] = Keccak256::digest(&data)
            .as_slice()
            .try_into()
            .expect("Wrong length");

        // TODO: need to test the whole thing is producing the expected bytes
        let msg = [
            "\x19Ethereum Signed Message:\n%d%s".as_bytes(),
            &data_hash.len().to_be_bytes(),
            &data_hash,
        ]
        .concat();

        let sig_hash = Keccak256::digest(msg)
            .as_slice()
            .try_into()
            .expect("Wrong length");

        Self {
            id,
            commands_ids,
            data,
            sig_hash,
            status: BatchedCommandsStatus::Signing,
        }
    }

    pub fn command_ids_hex_string(&self) -> String {
        // TODO: replace with serde to_string?
        self.commands_ids
            .iter()
            .fold(String::new(), |mut accum, command_id| {
                let hex_string = hex::encode(command_id);
                accum.push_str(&hex_string);
                accum
            })
    }
}

pub const ADMIN: Item<Addr> = Item::new("admin");
pub const SERVICE_INFO: Item<ServiceInfo> = Item::new("service");
pub const OUTBOUND_SETTINGS: Item<OutboundSettings> = Item::new("outbound_settings");
pub const AUTH_MODULE: Item<AuthMultisig> = Item::new("auth_module");
pub const COMMANDS_BATCH_QUEUE: Map<&[u8], CommandBatch> = Map::new("command_batchs");
