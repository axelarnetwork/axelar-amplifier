use crate::{
    signing::SigningSession,
    state::{SIGNING_SESSIONS, VERIFIER_SETS},
};
use cosmwasm_std::{DepsMut, Order, Response};

pub fn migrate_verifier_set_ids(
    deps: &mut DepsMut,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let all: Vec<_> = VERIFIER_SETS
        .range(deps.storage, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?;

    for v in all {
        VERIFIER_SETS.remove(deps.storage, &v.0);
        VERIFIER_SETS.save(deps.storage, &v.1.id(), &v.1)?;
    }

    Ok(Response::default())
}

pub fn migrate_signing_sessions(
    deps: &mut DepsMut,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let all: Vec<_> = SIGNING_SESSIONS
        .range(deps.storage, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?;

    for (session_id, session) in all {
        let verifier_set = VERIFIER_SETS.load(deps.storage, &session.verifier_set_id)?;
        let new_session = SigningSession {
            verifier_set_id: verifier_set.id(),
            ..session
        };
        SIGNING_SESSIONS.save(deps.storage, session_id, &new_session)?;
    }

    Ok(Response::default())
}

pub fn migrate(deps: &mut DepsMut) -> Result<Response, axelar_wasm_std::ContractError> {
    // signing sessions should be migrated first, so that way the old ids still point to the verifier sets
    migrate_signing_sessions(deps)?;
    migrate_verifier_set_ids(deps)
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
        migrate(&mut deps.as_mut()).unwrap();

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
}
