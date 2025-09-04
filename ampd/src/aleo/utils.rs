use std::str::FromStr as _;

use aleo_gmp_types::aleo_struct::generated_structs::{ContractCall, SignersRotated};
use aleo_utils::block_processor::IdValuePair;
use error_stack::{Result, ResultExt};
use snarkvm::prelude::{Field, Literal, LiteralType, Network, Plaintext, ToBits as _};

use crate::aleo::error::Error;

pub fn read_call_contract<N: Network>(outputs: &IdValuePair) -> Result<ContractCall<N>, Error> {
    let value = outputs.value.as_ref().ok_or(Error::CallContractNotFound)?;
    let plaintext = Plaintext::<N>::from_str(value)
        .map_err(Error::from)
        .attach_printable_lazy(|| format!("Failed to parse CallContract value: {value}"))?;

    let call_contract: ContractCall<N> = ContractCall::try_from(&plaintext)
        .map_err(Error::from)
        .attach_printable_lazy(|| {
            format!("Failed to convert plaintext to CallContract: {value}")
        })?;

    Ok(call_contract)
}

pub fn find_call_contract_in_outputs<N: Network>(
    outputs: &[IdValuePair],
    payload_hash: Field<N>,
) -> Option<String> {
    outputs.iter().find_map(|output| {
        let output_hash = output.value.as_ref().and_then(|value| {
            // The Plaintext is used here because we know that the CallContract payload is of Plaintext type
            let value = Plaintext::<N>::from_str(value).ok()?.to_bits_le();
            let group_hash = N::hash_to_group_bhp256(&value).ok()?;
            let literal = Literal::Group(group_hash);
            let literal = literal.cast_lossy(LiteralType::Field).ok()?;
            let Literal::Field(field) = literal else {
                return None;
            };
            Some(field)
        });

        match output_hash {
            Some(output_hash) if output_hash == payload_hash => output.value.clone(),
            _ => None,
        }
    })
}

/// Generic function to find a specific type in the outputs
pub fn find_signers_rotated_in_outputs<N: Network>(
    outputs: &[IdValuePair],
) -> Option<SignersRotated<N>> {
    outputs.iter().find_map(|output| {
        let value = output.value.as_ref()?;
        let plaintext = Plaintext::<N>::from_str(value).ok()?;
        let rotation: SignersRotated<N> = SignersRotated::try_from(&plaintext).ok()?;
        Some(rotation)
    })
}
