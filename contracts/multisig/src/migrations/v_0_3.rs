use crate::{state::VERIFIER_SETS, verifier_set::VerifierSet};
use cosmwasm_std::{DepsMut, Order, Response};
use cw_storage_plus::Map;

type VerifierSetId = str;
pub const WORKER_SETS: Map<&VerifierSetId, VerifierSet> = Map::new("worker_sets");

pub fn migrate_verifier_sets(deps: DepsMut) -> Result<Response, axelar_wasm_std::ContractError> {
    let all: Vec<_> = WORKER_SETS
        .range(deps.storage, None, None, Order::Ascending)
        .collect::<Result<Vec<_>, _>>()?;
    for v in all {
        VERIFIER_SETS.save(deps.storage, &v.0, &v.1)?;
        WORKER_SETS.remove(deps.storage, &v.0);
    }
    Ok(Response::default())
}

#[cfg(test)]
mod test {
    use crate::{
        migrations::v_0_3::WORKER_SETS,
        state::VERIFIER_SETS,
        test::common::{build_verifier_set, ecdsa_test_data::signers},
    };

    use cosmwasm_std::testing::mock_dependencies;

    use super::migrate_verifier_sets;

    #[test]
    fn should_be_able_to_migrate_worker_set_to_verifier_set() {
        let mut deps = mock_dependencies();
        let signers = signers();
        let mut worker_sets = vec![];
        let worker_set = build_verifier_set(crate::key::KeyType::Ecdsa, &signers);
        WORKER_SETS
            .save(&mut deps.storage, &worker_set.id(), &worker_set)
            .unwrap();
        worker_sets.push(worker_set);
        for s in signers {
            let new_signers = vec![s];
            let worker_set = build_verifier_set(crate::key::KeyType::Ecdsa, &new_signers);
            WORKER_SETS
                .save(&mut deps.storage, &worker_set.id(), &worker_set)
                .unwrap();
            worker_sets.push(worker_set);
        }
        let res = migrate_verifier_sets(deps.as_mut());
        assert!(res.is_ok());
        for worker_set in worker_sets {
            let res = VERIFIER_SETS
                .load(&mut deps.storage, &worker_set.id())
                .unwrap();
            assert_eq!(res, worker_set);
            assert!(WORKER_SETS
                .may_load(&mut deps.storage, &worker_set.id())
                .unwrap()
                .is_none())
        }
    }
}
