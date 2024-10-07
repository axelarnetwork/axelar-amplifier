use std::sync::OnceLock;

use starknet_core::types::FieldElement;
use starknet_core::utils::starknet_keccak;

pub mod contract_call;

// Since a keccak hash over a string is a deterministic operation,
// we can use `OnceLock` to eliminate useless hash calculations.
static CALL_CONTRACT_FELT: OnceLock<FieldElement> = OnceLock::new();

/// All Axelar event types supported by starknet
#[derive(Debug)]
pub enum EventType {
    ContractCall,
}

impl EventType {
    fn parse(event_type_felt: FieldElement) -> Option<Self> {
        let contract_call_type =
            CALL_CONTRACT_FELT.get_or_init(|| starknet_keccak("ContractCall".as_bytes()));

        if event_type_felt == *contract_call_type {
            Some(EventType::ContractCall)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod event_type_tests {
    use starknet_core::utils::starknet_keccak;

    use crate::starknet::events::EventType;

    #[test]
    fn parse_contract_call() {
        let contract_call_felt = starknet_keccak("ContractCall".as_bytes());
        assert!(matches!(
            EventType::parse(contract_call_felt),
            Some(EventType::ContractCall)
        ));
    }

    #[test]
    fn parse_unknown_event() {
        let contract_call_felt = starknet_keccak("UnknownEvent".as_bytes());
        assert!(EventType::parse(contract_call_felt).is_none());
    }
}
