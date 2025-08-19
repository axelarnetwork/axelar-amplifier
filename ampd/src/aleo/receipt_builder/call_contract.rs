use aleo_gmp_types::utils::AleoBitsToBytesExt as _;
use router_api::ChainName;
use sha3::Digest;
use snarkvm::prelude::{Address, FromBytes, Network};
use tracing::info;

use crate::types::Hash;

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
        let Ok(aleo_payload) = snarkvm::console::program::Value::<N>::from_bytes_le(&self.payload)
        else {
            return false;
        };

        let aleo_payload_bytes = aleo_payload.to_bytes();
        let aleo_payload_hash: [u8; 32] = sha3::Keccak256::digest(&aleo_payload_bytes).into();
        let aleo_payload_hash = Hash::from_slice(&aleo_payload_hash);

        // TODO: this is just for debugging, remove later
        info!(
            "transition_id: chain.'{}' == msg.'{}' ({})
            destination_address: chain.'{}' == msg.'{}' ({})
            destination_chain: chain.'{}' == msg.'{}' ({})
            source_address: chain.'{:?}' == msg.'{:?}' ({})
            payload_hash: chain.{:?} == msg.{:?} ({})",
            self.transition,
            message.tx_id,
            self.transition == message.tx_id,
            self.destination_address,
            message.destination_address,
            self.destination_address == message.destination_address,
            self.destination_chain,
            message.destination_chain,
            self.destination_chain == message.destination_chain,
            self.source_address,
            message.source_address,
            self.source_address == message.source_address,
            aleo_payload_hash,
            message.payload_hash,
            aleo_payload_hash == message.payload_hash
        );

        self.transition == message.tx_id
            && self.destination_address == message.destination_address
            && self.destination_chain == message.destination_chain
            && self.source_address == message.source_address
            && aleo_payload_hash == message.payload_hash
    }
}
