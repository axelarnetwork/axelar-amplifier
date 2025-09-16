use aleo_compatible_keccak::AleoBitsToBytesExt as _;
use axelar_wasm_std::hash::Hash;
use router_api::ChainName;
use sha3::Digest;
use snarkvm::prelude::{Address, FromBytes, Network, Value};

#[derive(Debug)]
pub struct CallContractReceipt<N: Network> {
    pub transition: N::TransitionID,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: Address<N>,
    pub payload: Vec<u8>,
}

impl<N: Network> PartialEq<crate::handlers::aleo_verify_msg::Message<N>>
    for CallContractReceipt<N>
{
    fn eq(&self, message: &crate::handlers::aleo_verify_msg::Message<N>) -> bool {
        let Ok(aleo_payload) = Value::<N>::from_bytes_le(&self.payload) else {
            return false;
        };

        let aleo_payload_bytes = aleo_payload.to_bytes();
        let aleo_payload_hash: Hash = sha3::Keccak256::digest(&aleo_payload_bytes).into();

        self.transition == message.tx_id
            && self.destination_address == message.destination_address
            && self.destination_chain == message.destination_chain
            && self.source_address == message.source_address
            && aleo_payload_hash == message.payload_hash
    }
}
