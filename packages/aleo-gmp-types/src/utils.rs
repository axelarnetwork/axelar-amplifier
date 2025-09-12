use aleo_gateway_types::Message;
use snarkvm_cosmwasm::prelude::{Group, Network, Plaintext, ToBits as _, Value};

use crate::error::Error;

pub fn bhp<N: Network>(input: impl TryInto<Value<N>>) -> Result<Group<N>, Error> {
    match input.try_into() {
        Ok(value) => Ok(N::hash_to_group_bhp256(&value.to_bits_le())?),
        Err(_) => Err(Error::ConversionFailed),
    }
}

// Use this function to compute the default message hash
pub fn default_message_hash<N: Network>() -> Group<N> {
    #![allow(clippy::unwrap_used)]
    let message = Message::<N>::default();
    let plaintext: Plaintext<N> = Plaintext::try_from(&message).unwrap();
    N::hash_to_group_bhp256(&plaintext.to_bits_le()).unwrap()
}
