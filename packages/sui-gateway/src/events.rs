use serde::{Deserialize, Serialize};
use sui_types::SuiAddress;

use super::{Bytes32, WeightedSigners};

#[derive(Serialize, Deserialize, Debug)]
pub struct SignersRotated {
    pub epoch: u64,
    pub signers_hash: Bytes32,
    pub signers: WeightedSigners,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ContractCall {
    pub source_id: SuiAddress,
    pub destination_chain: String,
    pub destination_address: String,
    pub payload: Vec<u8>,
    pub payload_hash: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::{ContractCall, SignersRotated};

    #[test]
    fn signers_rotated_should_serialize_and_deserialize_correct_bcs() {
        let bcs_bytes = bs58::decode("7VmsFWvv3atGxVB1oUDZAx6nRWoE1xiWYxqLP6mcWD3Rf4wFjhfMwjKmxjXHyVc9ZTdCRdt25rUCWxCBRGEuFogKfgXkUXSkHPxirMeS4R8kJn1pgA7bkMwQywgFnrmd1ceeWNCCBQuUGr83Gx8mbyZeN7W2EAct14rKQ5zukNZH6mKv7n4dmBasFm8vT").into_vec().unwrap();

        let event = bcs::from_bytes::<SignersRotated>(&bcs_bytes).unwrap();
        assert_eq!(bcs::to_bytes(&event).unwrap(), bcs_bytes);
    }

    #[test]
    fn contract_call_should_serialize_and_deserialize_correct_bcs() {
        let bcs_bytes = bs58::decode("3Q9LRQe3KX2E3VNVjMLzWhDwSrNBB2Js9KPoW1SFuj2HVTgp9SXezEPFtqYhddwb8AvKQSaednVibTWz9upFy51px2nnwKgfNcwK2JDckvMENBdEtTnpKJnfizA2vC9qzxiPtE17ANnK629HzkpMqPKpvJjDueJ9zMw").into_vec().unwrap();

        let event = bcs::from_bytes::<ContractCall>(&bcs_bytes).unwrap();
        assert_eq!(bcs::to_bytes(&event).unwrap(), bcs_bytes);
    }
}
