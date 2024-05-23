use cosmwasm_std::{DepsMut, Response};
use cw_storage_plus::Item;
use multisig::verifier_set::VerifierSet;

use crate::state::{CURRENT_VERIFIER_SET, NEXT_VERIFIER_SET};

const CURRENT_WORKER_SET: Item<VerifierSet> = Item::new("current_worker_set");
const NEXT_WORKER_SET: Item<VerifierSet> = Item::new("next_worker_set");

pub fn migrate_verifier_sets(deps: DepsMut) -> Result<Response, axelar_wasm_std::ContractError> {
    let current_worker_set = CURRENT_WORKER_SET.may_load(deps.storage)?;
    if let Some(current_worker_set) = current_worker_set {
        CURRENT_WORKER_SET.remove(deps.storage);
        CURRENT_VERIFIER_SET.save(deps.storage, &current_worker_set)?;
    }

    let next_worker_set = NEXT_WORKER_SET.may_load(deps.storage)?;
    if let Some(next_worker_set) = next_worker_set {
        NEXT_WORKER_SET.remove(deps.storage);
        NEXT_VERIFIER_SET.save(deps.storage, &next_worker_set)?;
    }

    Ok(Response::default())
}

#[cfg(test)]
mod test {
    use crate::{
        migrations::v_0_5::NEXT_WORKER_SET,
        state::{CURRENT_VERIFIER_SET, NEXT_VERIFIER_SET},
        test::test_data::new_verifier_set,
    };

    use cosmwasm_std::{testing::mock_dependencies, Uint128};

    use super::{migrate_verifier_sets, CURRENT_WORKER_SET};

    #[test]
    fn should_be_able_to_migrate_worker_set_to_verifier_set() {
        let mut deps = mock_dependencies();

        let worker_set = new_verifier_set();
        CURRENT_WORKER_SET
            .save(&mut deps.storage, &worker_set)
            .unwrap();

        let res = migrate_verifier_sets(deps.as_mut());
        assert!(res.is_ok());

        let verifier_set = CURRENT_VERIFIER_SET.load(&deps.storage).unwrap();
        assert_eq!(verifier_set, worker_set);

        assert!(NEXT_VERIFIER_SET.may_load(&deps.storage).unwrap().is_none());

        assert!(CURRENT_WORKER_SET
            .may_load(&deps.storage)
            .unwrap()
            .is_none());

        assert!(NEXT_WORKER_SET.may_load(&deps.storage).unwrap().is_none());
    }

    #[test]
    fn should_be_able_to_migrate_worker_set_to_verifier_set_mid_rotation() {
        let mut deps = mock_dependencies();
        let worker_set = new_verifier_set();

        CURRENT_WORKER_SET
            .save(&mut deps.storage, &worker_set)
            .unwrap();

        let mut next_worker_set = worker_set.clone();
        next_worker_set.threshold = worker_set.threshold.checked_add(Uint128::one()).unwrap();
        NEXT_WORKER_SET
            .save(&mut deps.storage, &next_worker_set)
            .unwrap();

        let res = migrate_verifier_sets(deps.as_mut());
        assert!(res.is_ok());

        let verifier_set = CURRENT_VERIFIER_SET.load(&deps.storage).unwrap();
        assert_eq!(verifier_set, worker_set);

        let next_verifier_set = NEXT_VERIFIER_SET.load(&deps.storage).unwrap();
        assert_eq!(next_verifier_set, next_worker_set);

        assert!(CURRENT_WORKER_SET
            .may_load(&deps.storage)
            .unwrap()
            .is_none());
        assert!(NEXT_WORKER_SET.may_load(&deps.storage).unwrap().is_none());
    }
}
