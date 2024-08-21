pub mod config;
mod errors;
pub mod evm_verify_msg;
pub mod evm_verify_verifier_set;
pub mod multisig;
pub mod mvx_verify_msg;
pub mod mvx_verify_verifier_set;
pub mod sui_verify_msg;
pub mod sui_verify_verifier_set;

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use events::Event;
    use tendermint::abci;

    use crate::types::TMAddress;

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
                .map(|cosmwasm_std::Attribute { key, value }| {
                    (STANDARD.encode(key), STANDARD.encode(value))
                }),
        )
        .try_into()
        .expect("should convert to ABCI event")
    }
}
