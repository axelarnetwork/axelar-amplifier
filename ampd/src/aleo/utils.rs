use std::str::FromStr as _;

use aleo_gateway_types::{ContractCall, SignersRotated};
use aleo_block_processor::IdValuePair;
use error_stack::{Result, ResultExt};
use snarkvm::prelude::{Field, Literal, LiteralType, Network, Plaintext, ToBits as _};

use crate::aleo::error::Error;

/// Reads and parses a `ContractCall` from the provided `IdValuePair`.
///
/// # Arguments
///
/// * `outputs` - An `IdValuePair` containing the contract call value.
///
/// # Returns
///
/// * `Result<ContractCall<N>, Error>` - The parsed `ContractCall` on success, or an error on failure.
pub fn read_call_contract<N: Network>(outputs: &IdValuePair) -> Result<ContractCall<N>, Error> {
    let value = outputs.value.as_ref().ok_or(Error::CallContractNotFound)?;
    let call_contract: ContractCall<N> = value
        .parse()
        .map_err(Error::from)
        .attach_printable_lazy(|| format!("Failed to parse CallContract value: {value}"))?;

    Ok(call_contract)
}

/// Searches for a contract call output in a slice of `IdValuePair` that matches the given payload hash.
///
/// # Arguments
///
/// * `outputs` - A slice of `IdValuePair` to search through.
/// * `payload_hash` - The hash of the payload to match.
///
/// # Returns
///
/// * `Option<String>` - The matching contract call value as a string, if found.
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
            Some(output_hash) if output_hash == payload_hash => {
                output.value.clone().map(|cow| cow.into_owned())
            }
            _ => None,
        }
    })
}

/// Searches for a `SignersRotated` event in a slice of `IdValuePair`.
///
/// # Arguments
///
/// * `outputs` - A slice of `IdValuePair` to search through.
///
/// # Returns
///
/// * `Option<SignersRotated<N>>` - The found `SignersRotated` event, if any.
pub fn find_signers_rotated_in_outputs<N: Network>(
    outputs: &[IdValuePair],
) -> Option<SignersRotated<N>> {
    outputs.iter().find_map(|output| {
        let value = output.value.as_ref()?;
        let rotation: SignersRotated<N> = value.parse().ok()?;
        Some(rotation)
    })
}
