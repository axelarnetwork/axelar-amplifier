use cosmwasm_std::{to_json_binary, Deps, QueryRequest, StdResult, Uint64, WasmQuery};
use error_stack::Result;
use multisig::multisig::Multisig;
use multisig::types::MultisigState;

use crate::error::ContractError;
use crate::msg::{ProofResponse, ProofStatus, VerifierSetResponse};
use crate::state::{
    CONFIG, CURRENT_VERIFIER_SET, MULTISIG_SESSION_PAYLOAD, NEXT_VERIFIER_SET, PAYLOAD,
};

pub fn proof(deps: Deps, multisig_session_id: Uint64) -> Result<ProofResponse, ContractError> {
    let config = CONFIG.load(deps.storage).map_err(ContractError::from)?;

    let payload_id = MULTISIG_SESSION_PAYLOAD
        .load(deps.storage, multisig_session_id.u64())
        .map_err(ContractError::from)?;

    let query_msg = multisig::msg::QueryMsg::Multisig {
        session_id: multisig_session_id,
    };

    let multisig: Multisig = deps
        .querier
        .query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.multisig.to_string(),
            msg: to_json_binary(&query_msg).map_err(ContractError::from)?,
        }))
        .map_err(ContractError::from)?;

    let payload = PAYLOAD
        .load(deps.storage, &payload_id)
        .map_err(ContractError::from)?;

    let status = match multisig.state {
        MultisigState::Pending => ProofStatus::Pending,
        MultisigState::Completed { .. } => {
            let execute_data = config.encoder.execute_data(
                &config.domain_separator,
                &multisig.verifier_set,
                multisig.optimize_signatures(),
                &payload,
            )?;
            ProofStatus::Completed { execute_data }
        }
    };

    Ok(ProofResponse {
        multisig_session_id,
        message_ids: payload.message_ids().unwrap_or_default(),
        payload,
        status,
    })
}

pub fn current_verifier_set(deps: Deps) -> StdResult<Option<VerifierSetResponse>> {
    CURRENT_VERIFIER_SET
        .may_load(deps.storage)
        .map(|op| op.map(|set| set.into()))
}

pub fn next_verifier_set(deps: Deps) -> StdResult<Option<VerifierSetResponse>> {
    NEXT_VERIFIER_SET
        .may_load(deps.storage)
        .map(|op| op.map(|set| set.into()))
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::mock_dependencies;

    use crate::state;
    use crate::test::test_data::new_verifier_set;

    #[test]
    fn next_verifier_set() {
        let mut deps = mock_dependencies();

        assert_eq!(None, super::next_verifier_set(deps.as_ref()).unwrap());

        state::NEXT_VERIFIER_SET
            .save(deps.as_mut().storage, &new_verifier_set())
            .unwrap();

        assert_eq!(
            Some(new_verifier_set().into()),
            super::next_verifier_set(deps.as_ref()).unwrap()
        );
    }
}
