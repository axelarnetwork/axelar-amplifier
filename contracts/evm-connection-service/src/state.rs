use std::{collections::HashMap, fmt::Display};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Decimal, Uint256, Uint64};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};
use sha3::{Digest, Keccak256};

use crate::{
    msg::{ActionMessage, ActionResponse},
    multisig::SigningSession,
    snapshot::Snapshot,
    utils::hash,
};

#[cw_serde]
pub struct ServiceInfo {
    pub service_registry: Addr,
    pub name: String,
    pub reward_pool: Addr,
    pub router_contract: Addr,
}

#[cw_serde]
pub struct InboundSettings {
    pub source_chain_name: String, // TODO: rename to inbound?
    pub gateway_address: Addr,     // TODO: rename to inbound?
    pub confirmation_height: Uint64,
    // pub voting_threshold: Decimal,
    // pub min_voter_count: Uint64,
    // pub voting_period: Uint64,
    // pub voting_grace_period: Uint64,
}

#[cw_serde]
pub struct OutboundSettings {
    pub destination_chain_id: Uint256, // TODO: rename to outbound?
    pub destination_chain_name: String, // TODO: this is wrong, service uses same chain for inbound and outbound, routing will give message to other service with the appropiate chain
                                        // pub signing_timeout: Uint64,
                                        // pub signing_grace_period: Uint64,
}

// #[cw_serde]
// pub enum PollState {
//     Pending,
//     Completed,
//     Failed,
// }

// impl Display for PollState {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             PollState::Pending => write!(f, "Pending"),
//             PollState::Completed => write!(f, "Completed"),
//             PollState::Failed => write!(f, "Failed"),
//         }
//     }
// }

// #[cw_serde]
// pub struct Participant {
//     pub address: Addr,
//     pub weight: Uint256,
// }

// #[cw_serde]
// pub struct PollMetadata {
//     // TODO: rename to poll
//     pub id: Uint64,
//     pub expires_at: Uint64, // TODO: this is used for end blocker, how is end blocker logic being handled in cosmwasm? Split endblockr logc and decide later who will trigger logic
//     pub result: Option<ActionResponse>,
//     pub state: PollState,
//     pub completed_at: Option<Uint64>,
//     pub snapshot: Snapshot,
//     pub message: ActionMessage,
// }

// impl PollMetadata {
//     pub fn new(id: Uint64, expires_at: Uint64, snapshot: Snapshot, message: ActionMessage) -> Self {
//         Self {
//             id,
//             expires_at,
//             result: None,
//             state: PollState::Pending,
//             completed_at: None,
//             snapshot,
//             message,
//         }
//     }
// }
// #[cw_serde]
// pub struct TalliedVote {
//     pub tally: Uint256,
//     pub data: ActionResponse,
//     pub poll_id: Uint64,
//     pub is_voter_late_namespace: String,
// }

// impl TalliedVote {
//     pub fn new(tally: Uint256, data: ActionResponse, poll_id: Uint64) -> Self {
//         let hash = hash(&data);
//         let namespace = format!("is_voter_late_{}{}", poll_id.u64(), hash);
//         Self {
//             tally,
//             data,
//             poll_id,
//             is_voter_late_namespace: namespace,
//         }
//     }

//     pub fn is_voter_late_map(&self) -> Map<&Addr, bool> {
//         Map::new(&self.is_voter_late_namespace)
//     }
// }

// pub fn is_voter_late_map(namespace: &str) -> Map<&Addr, bool> { // TODO: convert to HashMap?
//     Map::new(namespace)
// }

// pub struct TalliedVoteIndexes<'a> {
//     pub poll_id: MultiIndex<'a, u64, TalliedVote, (u64, u64)>,
// }

// impl<'a> IndexList<TalliedVote> for TalliedVoteIndexes<'a> {
//     fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<TalliedVote>> + '_> {
//         let v: Vec<&dyn Index<TalliedVote>> = vec![&self.poll_id];
//         Box::new(v.into_iter())
//     }
// }

// pub fn tallied_votes<'a>() -> IndexedMap<'a, (u64, u64), TalliedVote, TalliedVoteIndexes<'a>> {
//     let indexes = TalliedVoteIndexes {
//         poll_id: MultiIndex::new(
//             |_pk, d| d.poll_id.u64(),
//             "tallied_votes",
//             "tallied_votes__poll_id",
//         ),
//     };
//     IndexedMap::new("tallied_votes", indexes)
// }

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
    pub key_id: Uint64,
}

impl CommandBatch {
    pub fn new(
        block_height: u64,
        commands_ids: Vec<[u8; 32]>,
        data: Vec<u8>,
        key_id: Uint64,
    ) -> Self {
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
            key_id,
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

#[cw_serde]
pub enum KeyState {
    Inactive,
    Assigned,
    Active,
}

// TODO: keyrotation logic
#[cw_serde]
pub struct Key {
    pub id: Uint64,
    pub snapshot: Snapshot,
    pub signing_treshhold: Decimal,
    pub state: KeyState, // TODO: not being used right now
    pub pub_keys: HashMap<Addr, Binary>,
}

impl Key {
    pub fn new(
        id: u64,
        snapshot: Snapshot,
        signing_treshhold: Decimal,
        pub_keys: HashMap<Addr, Binary>,
    ) -> Self {
        Self {
            id: Uint64::from(id),
            snapshot,
            signing_treshhold,
            state: KeyState::Active,
            pub_keys,
        }
    }
}

pub const ADMIN: Item<Addr> = Item::new("admin");
pub const SERVICE_INFO: Item<ServiceInfo> = Item::new("service");
pub const INBOUND_SETTINGS: Item<InboundSettings> = Item::new("inbound_settings");
pub const OUTBOUND_SETTINGS: Item<OutboundSettings> = Item::new("outbound_settings");
pub const WORKERS_VOTING_POWER: Map<Addr, Uint256> = Map::new("workers_whitelist");
// pub const POLL_COUNTER: Item<u64> = Item::new("poll_counter");
// pub const POLLS: Map<u64, PollMetadata> = Map::new("polls");
pub const COMMANDS_BATCH_QUEUE: Map<&[u8], CommandBatch> = Map::new("command_batchs");
pub const KEYS_COUNTER: Item<u64> = Item::new("keys_counter");
pub const KEYS: Map<u64, Key> = Map::new("keys");
pub const SIGNING_SESSION_COUNTER: Item<u64> = Item::new("signing_session_counter");
pub const SIGNING_SESSIONS: Map<u64, SigningSession> = Map::new("signing_sessions");
