use crate::error::ContractError;
use crate::state::OUTGOING_MESSAGES;
use connection_router::state::CrossChainId;
use cosmwasm_std::{to_binary, Addr, Binary, Deps, QuerierWrapper, QueryRequest, WasmQuery};
use error_stack::{Result, ResultExt};

pub fn verify<'a>(
    querier: QuerierWrapper<'a>,
    verifier: &'a Addr,
) -> impl FnMut(aggregate_verifier::msg::QueryMsg) -> Result<Vec<(CrossChainId, bool)>, ContractError> + 'a
{
    move |msg| {
        querier
            .query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: verifier.to_string(),
                msg: to_binary(&msg).change_context(ContractError::QueryVerifier)?,
            }))
            .change_context(ContractError::QueryVerifier)
    }
}

pub fn get_messages(
    deps: Deps,
    cross_chain_ids: Vec<CrossChainId>,
) -> Result<Binary, ContractError> {
    let msgs = cross_chain_ids
        .into_iter()
        .map(|id| {
            OUTGOING_MESSAGES
                .load(deps.storage, id.clone())
                .change_context(ContractError::LoadOutgoingMessage)
                .attach_printable(id.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    to_binary(&msgs).change_context(ContractError::LoadOutgoingMessage)
}
