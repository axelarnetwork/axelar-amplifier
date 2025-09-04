use cosmwasm_std::HexBinary;
use snarkvm_cosmwasm::prelude::{Address, FromBytes, Group, Network, Signature, ToFields};

use crate::ContractError;

pub fn verify_signature<N: Network>(
    signature: HexBinary,
    message: HexBinary,
    public_key: HexBinary,
) -> Result<bool, ContractError> {
    let signature = Signature::<N>::from_bytes_le(&signature)?;

    let address = Address::<N>::from_bytes_le(&public_key)?;

    let group_value = Group::<N>::from_bytes_le(&message)?;
    let res = signature.verify(&address, &group_value.to_fields()?);

    Ok(res)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use aleo_gmp_types::utils::ToBytesExt;
    use axelar_wasm_std::hash::Hash;
    use snarkos_account::Account;
    use snarkvm_cosmwasm::console::network::TestnetV0;
    use snarkvm_cosmwasm::prelude::ToBytes as _;

    use super::*;

    type CurrentNetwork = TestnetV0;

    #[test]
    fn test_verify_signature() {
        let message = Group::<CurrentNetwork>::from_str("2group").unwrap();

        let aleo_account =
            Account::new(&mut rand::thread_rng()).expect("Failed to create Aleo account");
        let encoded_signature = aleo_account
            .sign(&message.to_fields().unwrap(), &mut rand::thread_rng())
            .and_then(|signature| signature.to_bytes_le())
            .expect("Failed to sign message")
            .into();

        let message: Hash = message.to_bytes_le_array().unwrap();
        let message = message.into();
        let public_key: Address<CurrentNetwork> = aleo_account.address();
        let encoded_public_key = public_key
            .to_bytes_le()
            .expect("Failed to get address")
            .into();

        assert!(
            verify_signature::<CurrentNetwork>(encoded_signature, message, encoded_public_key)
                .expect("Failed to verify signature"),
        );
    }
}
