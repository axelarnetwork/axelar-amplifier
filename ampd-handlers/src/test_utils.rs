use std::convert::TryInto;

use cosmrs::AccountId;
use events::Event;
use tendermint::abci;

use ampd::types::TMAddress;

const PREFIX: &str = "axelar";

/// Convert a CosmWasm event into an ABCI event
pub fn into_structured_event(
    event: impl Into<cosmwasm_std::Event>,
    contract_address: &TMAddress,
) -> Event {
    let mut event: cosmwasm_std::Event = event.into();

    event.ty = format!("wasm-{}", event.ty);
    event = event.add_attribute("_contract_address", contract_address.to_string());

    abci::Event::new(
        event.ty,
        event
            .attributes
            .into_iter()
            .map(|cosmwasm_std::Attribute { key, value }| (key, value)),
    )
    .try_into()
    .expect("should convert to ABCI event")
}

pub fn participants(n: u8, verifier: Option<TMAddress>) -> Vec<TMAddress> {
    (0..n)
        .map(|i| {
            AccountId::new(PREFIX, &[i; AccountId::MAX_LENGTH])
                .unwrap()
                .into()
        })
        .chain(verifier)
        .collect()
}
