#![allow(deprecated)]

use axelar_wasm_std::killswitch::State;
use axelar_wasm_std::{killswitch, nonempty, permission_control};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, StdError, Storage};
use cw2::VersionError;
use cw_storage_plus::Item;
use itertools::Itertools;
use router_api::ChainName;

use crate::contract::CONTRACT_NAME;
use crate::signing::SigningSession;
use crate::state::{AUTHORIZED_CALLERS, SIGNING_SESSIONS, VERIFIER_SETS};

const BASE_VERSION: &str = "0.4.1";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error(transparent)]
    Version(#[from] VersionError),
    #[error(transparent)]
    NonEmpty(#[from] nonempty::Error),
}

pub fn migrate(
    storage: &mut dyn Storage,
    admin: Addr,
    authorized_callers: Vec<(Addr, ChainName)>,
) -> Result<(), Error> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    killswitch::init(storage, State::Disengaged)?;

    let config = ensure_expiry_height_is_not_zero(storage)?;
    permission_control::set_governance(storage, &config.governance)?;
    permission_control::set_admin(storage, &admin)?;
    migrate_config(storage, config)?;
    migrate_authorized_callers(storage, authorized_callers)?;
    migrate_signing_sessions(storage)?;
    migrate_verifier_set_ids(storage)?;
    Ok(())
}

fn migrate_authorized_callers(
    storage: &mut dyn Storage,
    authorized_callers: Vec<(Addr, ChainName)>,
) -> Result<(), Error> {
    AUTHORIZED_CALLERS.clear(storage);
    authorized_callers
        .iter()
        .map(|(contract_address, chain_name)| {
            AUTHORIZED_CALLERS.save(storage, contract_address, chain_name)
        })
        .try_collect()?;
    Ok(())
}

pub fn migrate_signing_sessions(storage: &mut dyn Storage) -> Result<(), Error> {
    let all: Vec<_> = SIGNING_SESSIONS
        .range(storage, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?;

    for (session_id, session) in all {
        let verifier_set = VERIFIER_SETS.load(storage, &session.verifier_set_id)?;
        let new_session = SigningSession {
            verifier_set_id: verifier_set.id(),
            ..session
        };
        SIGNING_SESSIONS.save(storage, session_id, &new_session)?;
    }

    Ok(())
}

pub fn migrate_verifier_set_ids(storage: &mut dyn Storage) -> Result<(), Error> {
    let all: Vec<_> = VERIFIER_SETS
        .range(storage, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?;

    for v in all {
        VERIFIER_SETS.remove(storage, &v.0);
        VERIFIER_SETS.save(storage, &v.1.id(), &v.1)?;
    }

    Ok(())
}

fn ensure_expiry_height_is_not_zero(storage: &mut dyn Storage) -> Result<Config, Error> {
    CONFIG.update(storage, |mut config| {
        if config.block_expiry == 0 {
            config.block_expiry = 10;
        }
        Ok(config)
    })
}

fn migrate_config(storage: &mut dyn Storage, config: Config) -> Result<(), Error> {
    let new_config = crate::state::Config {
        rewards_contract: config.rewards_contract,
        block_expiry: nonempty::Uint64::try_from(config.block_expiry)?,
    };

    CONFIG.remove(storage);
    crate::state::CONFIG.save(storage, &new_config)?;
    Ok(())
}

#[cw_serde]
#[deprecated(since = "0.4.1", note = "only used during migration")]
struct Config {
    pub governance: Addr,
    pub rewards_contract: Addr,
    pub block_expiry: u64, // number of blocks after which a signing session expires
}

#[deprecated(since = "0.4.1", note = "only used during migration")]
const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
mod tests {
    use axelar_wasm_std::nonempty;
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, DepsMut, Env, HexBinary, MessageInfo, Response, Uint64};
    use router_api::ChainName;

    use crate::contract::migrations::v0_4_1::{self, BASE_VERSION};
    use crate::contract::{execute, query, CONTRACT_NAME};
    use crate::msg::ExecuteMsg::{DisableSigning, SubmitSignature};
    use crate::signing::SigningSession;
    use crate::state::{SIGNING_SESSIONS, SIGNING_SESSION_COUNTER, VERIFIER_SETS};
    use crate::test::common::build_verifier_set;
    use crate::test::common::ecdsa_test_data::signers;
    use crate::ContractError;

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: "governance".to_string(),
                rewards_address: "rewards".to_string(),
                block_expiry: 100,
            },
        )
        .unwrap();

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v0_4_1::migrate(deps.as_mut().storage, Addr::unchecked("admin"), vec![]).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, BASE_VERSION).unwrap();

        assert!(v0_4_1::migrate(deps.as_mut().storage, Addr::unchecked("admin"), vec![]).is_ok());
    }

    #[test]
    fn migrate_config() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: "governance".to_string(),
                rewards_address: "rewards".to_string(),
                block_expiry: 0,
            },
        )
        .unwrap();

        assert!(v0_4_1::migrate(deps.as_mut().storage, Addr::unchecked("admin"), vec![]).is_ok());

        assert!(v0_4_1::CONFIG.load(deps.as_mut().storage).is_err());

        let new_config = crate::state::CONFIG.load(deps.as_mut().storage);
        assert!(new_config.is_ok());
        let new_config = new_config.unwrap();
        assert_eq!(
            new_config.block_expiry,
            nonempty::Uint64::try_from(10).unwrap()
        );
    }

    #[test]
    fn permissions_are_set_after_migration_and_contract_can_be_disabled() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: "governance".to_string(),
                rewards_address: "rewards".to_string(),
                block_expiry: 100,
            },
        )
        .unwrap();

        assert!(v0_4_1::migrate(deps.as_mut().storage, Addr::unchecked("admin"), vec![]).is_ok());

        // contract is enabled
        assert!(!execute(
            deps.as_mut(),
            mock_env(),
            mock_info("any_addr", &[]),
            SubmitSignature {
                session_id: 0u64.into(),
                signature: HexBinary::from_hex("04").unwrap(),
            }
        )
        .unwrap_err()
        .to_string()
        .contains(&ContractError::SigningDisabled.to_string()));

        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info("any_addr", &[]),
            DisableSigning
        )
        .is_err());
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            DisableSigning
        )
        .is_ok());
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info("governance", &[]),
            DisableSigning
        )
        .is_ok());

        // contract is disabled
        assert!(execute(
            deps.as_mut(),
            mock_env(),
            mock_info("any_addr", &[]),
            SubmitSignature {
                session_id: 0u64.into(),
                signature: HexBinary::from_hex("04").unwrap(),
            }
        )
        .unwrap_err()
        .to_string()
        .contains(&ContractError::SigningDisabled.to_string()));
    }

    #[test]
    fn callers_are_authorized() {
        let mut deps = mock_dependencies();
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: "governance".to_string(),
                rewards_address: "rewards".to_string(),
                block_expiry: 100,
            },
        )
        .unwrap();

        let prover = Addr::unchecked("prover1");
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        assert!(v0_4_1::migrate(
            deps.as_mut().storage,
            Addr::unchecked("admin"),
            vec![(prover.clone(), chain_name.clone())]
        )
        .is_ok());
        assert!(query::caller_authorized(deps.as_ref(), prover, chain_name).unwrap());
    }

    #[test]
    fn should_be_able_to_migrate_verifier_set_ids() {
        let mut deps = mock_dependencies();

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                governance_address: "governance".to_string(),
                rewards_address: "rewards".to_string(),
                block_expiry: 100,
            },
        )
        .unwrap();
        let signers = signers();
        let verifier_set = build_verifier_set(crate::key::KeyType::Ecdsa, &signers);
        VERIFIER_SETS
            .save(&mut deps.storage, "foobar", &verifier_set)
            .unwrap();
        let signing_session = SigningSession {
            id: Uint64::one(),
            verifier_set_id: "foobar".to_string(),
            chain_name: "ethereum".parse().unwrap(),
            msg: HexBinary::from([2; 32]).try_into().unwrap(),
            state: crate::types::MultisigState::Pending,
            expires_at: 100,
            sig_verifier: None,
        };
        SIGNING_SESSIONS
            .save(
                &mut deps.storage,
                signing_session.id.u64(),
                &signing_session,
            )
            .unwrap();

        v0_4_1::migrate(deps.as_mut().storage, Addr::unchecked("admin"), vec![]).unwrap();

        let new_verifier_set = VERIFIER_SETS
            .load(&deps.storage, &verifier_set.id())
            .unwrap();
        assert_eq!(new_verifier_set, verifier_set);

        let expected_signing_session = SigningSession {
            verifier_set_id: verifier_set.id(),
            ..signing_session
        };
        let new_signing_session = SIGNING_SESSIONS
            .load(&deps.storage, expected_signing_session.id.u64())
            .unwrap();
        assert_eq!(new_signing_session, expected_signing_session);
    }

    #[deprecated(since = "0.4.1", note = "only used to test the migration")]
    fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, BASE_VERSION)?;

        let config = v0_4_1::Config {
            governance: deps.api.addr_validate(&msg.governance_address)?,
            rewards_contract: deps.api.addr_validate(&msg.rewards_address)?,
            block_expiry: msg.block_expiry,
        };

        v0_4_1::CONFIG.save(deps.storage, &config)?;

        SIGNING_SESSION_COUNTER.save(deps.storage, &Uint64::zero())?;

        Ok(Response::default())
    }

    #[cw_serde]
    #[deprecated(since = "0.4.1", note = "only used to test the migration")]
    struct InstantiateMsg {
        // the governance address is allowed to modify the authorized caller list for this contract
        pub governance_address: String,
        pub rewards_address: String,
        pub block_expiry: u64,
    }
}
