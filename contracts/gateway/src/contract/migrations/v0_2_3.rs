#![allow(deprecated)]

use std::any::type_name;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, StdResult, Storage};
use cw_storage_plus::{Key, KeyDeserialize, Map, PrimaryKey};
use router_api::{Address, ChainName, ChainNameRaw};

use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};

const BASE_VERSION: &str = "0.2.3";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    delete_outgoing_messages(storage);

    cw2::set_contract_version(storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(())
}

fn delete_outgoing_messages(storage: &mut dyn Storage) {
    OUTGOING_MESSAGES.clear(storage);
}

#[deprecated(since = "0.2.3", note = "only used during migration")]
const OUTGOING_MESSAGES_NAME: &str = "outgoing_messages";

#[deprecated(since = "0.2.3", note = "only used during migration")]
const OUTGOING_MESSAGES: Map<&CrossChainId, Message> = Map::new(OUTGOING_MESSAGES_NAME);

#[cw_serde]
#[derive(Eq, Hash)]
#[deprecated(since = "0.2.3", note = "only used during migration")]
pub struct Message {
    pub cc_id: CrossChainId,
    pub source_address: Address,
    pub destination_chain: ChainName,
    pub destination_address: Address,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub payload_hash: [u8; 32],
}

#[cw_serde]
#[derive(Eq, Hash)]
#[deprecated(since = "0.2.3", note = "only used during migration")]
pub struct CrossChainId {
    pub chain: ChainNameRaw,
    pub id: nonempty::String,
}

impl PrimaryKey<'_> for CrossChainId {
    type Prefix = ChainNameRaw;
    type SubPrefix = ();
    type Suffix = String;
    type SuperSuffix = (ChainNameRaw, String);

    fn key(&self) -> Vec<Key> {
        let mut keys = self.chain.key();
        keys.extend(self.id.key());
        keys
    }
}

impl KeyDeserialize for &CrossChainId {
    type Output = CrossChainId;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let (chain, id) = <(ChainNameRaw, String)>::from_vec(value)?;
        Ok(CrossChainId {
            chain,
            id: id
                .try_into()
                .map_err(|err| StdError::parse_err(type_name::<nonempty::String>(), err))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
    use error_stack::ResultExt;

    use crate::contract::migrations::v0_2_3;
    use crate::contract::{Error, CONTRACT_NAME, CONTRACT_VERSION};
    use crate::msg::InstantiateMsg;
    use crate::state;
    use crate::state::Config;

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v0_2_3::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, v0_2_3::BASE_VERSION)
            .unwrap();

        assert!(v0_2_3::migrate(deps.as_mut().storage).is_ok());
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        v0_2_3::migrate(deps.as_mut().storage).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    fn instantiate_contract(deps: DepsMut) {
        instantiate(
            deps,
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                verifier_address: "verifier".to_string(),
                router_address: "router".to_string(),
            },
        )
        .unwrap();
    }

    #[test]
    fn migrate_outgoing_messages() {
        let mut deps = mock_dependencies();

        instantiate_contract(deps.as_mut());

        let msgs = vec![
            v0_2_3::Message {
                cc_id: v0_2_3::CrossChainId {
                    id: "id1".try_into().unwrap(),
                    chain: "chain1".try_into().unwrap(),
                },
                source_address: "source-address".parse().unwrap(),
                destination_chain: "destination".parse().unwrap(),
                destination_address: "destination-address".parse().unwrap(),
                payload_hash: [1; 32],
            },
            v0_2_3::Message {
                cc_id: v0_2_3::CrossChainId {
                    id: "id2".try_into().unwrap(),
                    chain: "chain2".try_into().unwrap(),
                },
                source_address: "source-address2".parse().unwrap(),
                destination_chain: "destination2".parse().unwrap(),
                destination_address: "destination-address2".parse().unwrap(),
                payload_hash: [2; 32],
            },
            v0_2_3::Message {
                cc_id: v0_2_3::CrossChainId {
                    id: "id3".try_into().unwrap(),
                    chain: "chain3".try_into().unwrap(),
                },
                source_address: "source-address3".parse().unwrap(),
                destination_chain: "destination3".parse().unwrap(),
                destination_address: "destination-address3".parse().unwrap(),
                payload_hash: [3; 32],
            },
        ];

        for msg in msgs.iter() {
            v0_2_3::OUTGOING_MESSAGES
                .save(deps.as_mut().storage, &msg.cc_id, msg)
                .unwrap();
        }

        assert!(v0_2_3::migrate(deps.as_mut().storage).is_ok());

        assert!(v0_2_3::OUTGOING_MESSAGES.is_empty(deps.as_ref().storage))
    }

    #[deprecated(since = "0.2.3", note = "only used to test the migration")]
    pub fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, v0_2_3::BASE_VERSION)?;

        let router = deps
            .api
            .addr_validate(&msg.router_address)
            .change_context(Error::InvalidAddress)
            .attach_printable(msg.router_address)?;

        let verifier = deps
            .api
            .addr_validate(&msg.verifier_address)
            .change_context(Error::InvalidAddress)
            .attach_printable(msg.verifier_address)?;

        state::save_config(deps.storage, &Config { verifier, router })
            .change_context(Error::InvalidStoreAccess)?;

        Ok(Response::new())
    }
}
