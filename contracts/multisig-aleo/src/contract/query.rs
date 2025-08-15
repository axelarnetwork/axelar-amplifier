use cosmwasm_std::HexBinary;
use snarkvm_cosmwasm::prelude::{Address, FromBytes, Network, Signature};

use crate::ContractError;

pub fn verify_signature<N: Network>(
    signature: HexBinary,
    message: HexBinary,
    public_key: HexBinary,
) -> Result<bool, ContractError> {
    let signature = Signature::<N>::from_bytes_le(&signature)?;

    let address = Address::<N>::from_bytes_le(&public_key)?;

    let res = signature.verify_bytes(&address, &message);

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkos_account::Account;
    use snarkvm_cosmwasm::{console::network::TestnetV0, prelude::ToBytes as _};

    type CurrentNetwork = TestnetV0;

    #[test]
    fn test_verify_signature() {
        let message = [
            30, 165, 51, 99, 240, 22, 44, 209, 224, 46, 25, 4, 49, 49, 114, 238, 209, 48, 186, 136,
            95, 224, 128, 254, 19, 109, 54, 40, 214, 206, 187, 13,
        ];

        let aleo_account =
            Account::new(&mut rand::thread_rng()).expect("Failed to create Aleo account");
        let encoded_signature = aleo_account
            .sign_bytes(&message, &mut rand::thread_rng())
            .and_then(|signature| signature.to_bytes_le())
            .expect("Failed to sign message")
            .into();

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
