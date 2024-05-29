use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, StdResult, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};

use axelar_wasm_std::{
    counter,
    hash::Hash,
    msg_id::MessageIdFormat,
    nonempty,
    voting::{PollId, WeightedPoll},
    MajorityThreshold,
};
use multisig::verifier_set::VerifierSet;
use router_api::{ChainName, Message};

use crate::error::ContractError;

#[cw_serde]
pub struct Config {
    pub governance: Addr,
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: u64, // number of blocks after which a poll expires
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_contract: Addr,
    pub msg_id_format: MessageIdFormat,
}

#[cw_serde]
pub enum Poll {
    Messages(WeightedPoll),
    ConfirmVerifierSet(WeightedPoll),
}

impl Poll {
    pub fn try_map<F, E>(self, func: F) -> Result<Self, E>
    where
        F: FnOnce(WeightedPoll) -> Result<WeightedPoll, E>,
        E: From<ContractError>,
    {
        match self {
            Poll::Messages(poll) => Ok(Poll::Messages(func(poll)?)),
            Poll::ConfirmVerifierSet(poll) => Ok(Poll::ConfirmVerifierSet(func(poll)?)),
        }
    }
}

#[cw_serde]
pub struct PollContent<T> {
    pub content: T, // content is stored for migration purposes in case the hash changes
    pub poll_id: PollId,
    pub index_in_poll: u32,
}

impl PollContent<Message> {
    pub fn new(message: Message, poll_id: PollId, index_in_poll: usize) -> Self {
        Self {
            content: message,
            poll_id,
            index_in_poll: index_in_poll.try_into().unwrap(),
        }
    }
}

impl PollContent<VerifierSet> {
    pub fn new(verifier_set: VerifierSet, poll_id: PollId) -> Self {
        Self {
            content: verifier_set,
            poll_id,
            index_in_poll: 0,
        }
    }
}

pub const POLL_ID: counter::Counter<PollId> = counter::Counter::new("poll_id");

pub const POLLS: Map<PollId, Poll> = Map::new("polls");

pub const CONFIG: Item<Config> = Item::new("config");

pub struct PollMessagesIndexes<'a> {
    pub poll_idx: PollIndexMessages<'a>,
}

pub struct PollIndexMessages<'a>(MultiIndex<'a, (String, u32), PollContent<Message>, &'a Hash>);

impl<'a> PollIndexMessages<'a> {
    pub fn new(
        idx_fn: fn(&[u8], &PollContent<Message>) -> (String, u32),
        pk_namespace: &'a str,
        idx_namespace: &'a str,
    ) -> Self {
        PollIndexMessages(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }

    pub fn load_message(
        &self,
        storage: &dyn Storage,
        poll_id: PollId,
        index_in_poll: u32,
    ) -> StdResult<Option<Message>> {
        match self
            .0
            .prefix((poll_id.to_string(), index_in_poll))
            .range(storage, None, None, Order::Ascending)
            .collect::<Result<Vec<([u8; 32], PollContent<Message>)>, _>>()?
            .as_slice()
        {
            [] => Ok(None),
            [(_, content)] => Ok(Some(content.content.to_owned())),
            _ => panic!("More than one message for poll_id and index_in_poll"),
        }
    }
}

const POLL_MESSAGES_PKEY: &str = "poll_messages";

pub fn poll_messages<'a>() -> IndexedMap<'a, &'a Hash, PollContent<Message>, PollMessagesIndexes<'a>>
{
    return IndexedMap::new(
        POLL_MESSAGES_PKEY,
        PollMessagesIndexes {
            poll_idx: PollIndexMessages::new(
                |_pk: &[u8], d: &PollContent<Message>| (d.poll_id.to_string(), d.index_in_poll),
                POLL_MESSAGES_PKEY,
                "polls",
            ),
        },
    );
}

impl<'a> IndexList<PollContent<Message>> for PollMessagesIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<PollContent<Message>>> + '_> {
        let v: Vec<&dyn Index<PollContent<Message>>> = vec![&self.poll_idx.0];
        Box::new(v.into_iter())
    }
}

pub struct PollVerifierSetsIndexes<'a> {
    pub poll_idx: PollIndexVerifierSets<'a>,
}

pub struct PollIndexVerifierSets<'a>(MultiIndex<'a, String, PollContent<VerifierSet>, &'a Hash>);

impl<'a> PollIndexVerifierSets<'a> {
    pub fn new(
        idx_fn: fn(&[u8], &PollContent<VerifierSet>) -> String,
        pk_namespace: &'a str,
        idx_namespace: &'a str,
    ) -> Self {
        PollIndexVerifierSets(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }

    pub fn load_verifier_set(
        &self,
        storage: &dyn Storage,
        poll_id: PollId,
    ) -> StdResult<Option<VerifierSet>> {
        match self
            .0
            .prefix(poll_id.to_string())
            .range(storage, None, None, Order::Ascending)
            .collect::<Result<Vec<([u8; 32], PollContent<VerifierSet>)>, _>>()?
            .as_slice()
        {
            [] => Ok(None),
            [(_, content)] => Ok(Some(content.content.to_owned())),
            _ => panic!("More than one verifier_set for poll_id and index_in_poll"),
        }
    }
}

const POLL_VERIFIER_SETS_PKEY: &str = "poll_verifier_sets";

pub fn poll_verifier_sets<'a>(
) -> IndexedMap<'a, &'a Hash, PollContent<VerifierSet>, PollVerifierSetsIndexes<'a>> {
    return IndexedMap::new(
        POLL_VERIFIER_SETS_PKEY,
        PollVerifierSetsIndexes {
            poll_idx: PollIndexVerifierSets::new(
                |_pk: &[u8], d: &PollContent<VerifierSet>| d.poll_id.to_string(),
                POLL_VERIFIER_SETS_PKEY,
                "polls",
            ),
        },
    );
}

impl<'a> IndexList<PollContent<VerifierSet>> for PollVerifierSetsIndexes<'a> {
    fn get_indexes(
        &'_ self,
    ) -> Box<dyn Iterator<Item = &'_ dyn Index<PollContent<VerifierSet>>> + '_> {
        let v: Vec<&dyn Index<PollContent<VerifierSet>>> = vec![&self.poll_idx.0];
        Box::new(v.into_iter())
    }
}
