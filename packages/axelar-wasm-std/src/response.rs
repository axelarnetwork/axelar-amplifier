use cosmwasm_std::{from_json, CosmosMsg, Response, StdError, WasmMsg};
use serde::de::DeserializeOwned;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("no wasm msg found")]
    NotFound,
    #[error("multiple msgs found in the response")]
    MultipleMsgsFound,
}

/// Get a msg wrapped inside a `WasmMsg::Execute` from a `Response`.
/// If there are no wasm messages or more than one message in the response, this returns an error.
pub fn inspect_response_msg<T, D>(response: Response<T>) -> Result<D, Error>
where
    D: DeserializeOwned,
{
    let mut followup_messages = response.messages.into_iter();

    let msg = followup_messages.next().ok_or(Error::NotFound)?.msg;

    if followup_messages.next().is_some() {
        return Err(Error::MultipleMsgsFound);
    }

    match msg {
        CosmosMsg::Wasm(WasmMsg::Execute { msg, .. }) => Ok(from_json(msg)?),
        _ => Err(Error::NotFound),
    }
}
