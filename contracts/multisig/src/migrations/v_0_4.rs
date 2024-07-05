use crate::state::{SIGNING_SESSIONS, VERIFIER_SETS};
use cosmwasm_std::{DepsMut, Order, Response, Storage};

fn migrate_verifier_set_ids(
    store: &mut dyn Storage,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let all: Vec<_> = VERIFIER_SETS
        .range(store, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?;

    for v in all {
        VERIFIER_SETS.remove(store, &v.0);
        VERIFIER_SETS.save(store, &v.1.id(), &v.1)?;
    }

    Ok(Response::default())
}

fn remove_all_signing_sessions(
    store: &mut dyn Storage,
) -> Result<Response, axelar_wasm_std::ContractError> {
    SIGNING_SESSIONS.clear(store);

    Ok(Response::default())
}

pub fn migrate(deps: DepsMut) -> Result<Response, axelar_wasm_std::ContractError> {
    remove_all_signing_sessions(deps.storage)?;
    migrate_verifier_set_ids(deps.storage)
}

#[cfg(test)]
mod test {
    use crate::{
        signing::SigningSession,
        state::{SIGNING_SESSIONS, VERIFIER_SETS},
        test::common::{build_verifier_set, ecdsa_test_data::signers},
    };

    use cosmwasm_std::{testing::mock_dependencies, HexBinary, Uint64};

    use super::migrate;

    #[test]
    fn should_be_able_to_migrate_verifier_set_ids() {
        let mut deps = mock_dependencies();
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

        migrate(deps.as_mut()).unwrap();

        let new_verifier_set = VERIFIER_SETS.load(&deps.storage, &verifier_set.id());
        assert!(new_verifier_set.is_ok(), "{:?}", new_verifier_set);
        assert_eq!(new_verifier_set.unwrap(), verifier_set);

        let loaded_signing_session = SIGNING_SESSIONS.load(&deps.storage, signing_session.id.u64());
        assert!(loaded_signing_session.is_err());
    }
}
