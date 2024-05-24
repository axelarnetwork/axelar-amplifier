use axelar_wasm_std::voting::Vote;
use ethers::contract::EthLogDecode;
use ethers::types::{Log, TransactionReceipt, H256};
use evm_gateway::{IAxelarAmplifierGatewayEvents, WeightedSigners};
use num_traits::cast;

use crate::handlers::evm_verify_msg::Message;
use crate::handlers::evm_verify_verifier_set::VerifierSetConfirmation;
use crate::types::EVMAddress;

struct IAxelarGatewayEventsWithLog<'a>(&'a Log, IAxelarAmplifierGatewayEvents);

impl PartialEq<IAxelarGatewayEventsWithLog<'_>> for &Message {
    fn eq(&self, other: &IAxelarGatewayEventsWithLog<'_>) -> bool {
        let IAxelarGatewayEventsWithLog(log, event) = other;

        match event {
            IAxelarAmplifierGatewayEvents::ContractCallFilter(event) => {
                log.transaction_hash == Some(self.tx_id)
                    && event.sender == self.source_address
                    && self.destination_chain == event.destination_chain
                    && event.destination_contract_address == self.destination_address
                    && event.payload_hash == self.payload_hash.as_bytes()
            }
            _ => false,
        }
    }
}

impl PartialEq<IAxelarGatewayEventsWithLog<'_>> for &VerifierSetConfirmation {
    fn eq(&self, other: &IAxelarGatewayEventsWithLog<'_>) -> bool {
        let IAxelarGatewayEventsWithLog(log, event) = other;
        match event {
            IAxelarAmplifierGatewayEvents::SignersRotatedFilter(event) => {
                let weighted_signers = match WeightedSigners::try_from(&self.verifier_set) {
                    Ok(signers) => signers,
                    Err(_) => return false,
                };

                log.transaction_hash == Some(self.tx_id)
                    && event.signers_hash == weighted_signers.hash()
                    && event.signers == weighted_signers.abi_encode()
            }
            _ => false,
        }
    }
}

fn has_failed(tx_receipt: &TransactionReceipt) -> bool {
    tx_receipt.status == Some(0u64.into())
}

fn get_event<'a>(
    gateway_address: &EVMAddress,
    tx_receipt: &'a TransactionReceipt,
    log_index: u32,
) -> Option<IAxelarGatewayEventsWithLog<'a>> {
    let log_index: usize = cast(log_index).expect("log_index must be a valid usize");

    tx_receipt
        .logs
        .get(log_index)
        .filter(|log| log.address == *gateway_address)
        .and_then(
            |log| match IAxelarAmplifierGatewayEvents::decode_log(&log.clone().into()) {
                Ok(event) => Some(IAxelarGatewayEventsWithLog(log, event)),
                Err(_) => None,
            },
        )
}

fn verify<'a, V>(
    gateway_address: &EVMAddress,
    tx_receipt: &'a TransactionReceipt,
    to_verify: V,
    expected_transaction_hash: H256,
    expected_event_index: u32,
) -> Vote
where
    V: PartialEq<IAxelarGatewayEventsWithLog<'a>>,
{
    if has_failed(tx_receipt) {
        return Vote::FailedOnChain;
    }

    match get_event(gateway_address, tx_receipt, expected_event_index) {
        Some(event)
            if tx_receipt.transaction_hash == expected_transaction_hash && to_verify == event =>
        {
            Vote::SucceededOnChain
        }
        _ => Vote::NotFound,
    }
}

pub fn verify_message(
    gateway_address: &EVMAddress,
    tx_receipt: &TransactionReceipt,
    msg: &Message,
) -> Vote {
    verify(gateway_address, tx_receipt, msg, msg.tx_id, msg.event_index)
}

pub fn verify_worker_set(
    gateway_address: &EVMAddress,
    tx_receipt: &TransactionReceipt,
    worker_set: &VerifierSetConfirmation,
) -> Vote {
    verify(
        gateway_address,
        tx_receipt,
        worker_set,
        worker_set.tx_id,
        worker_set.event_index,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axelar_wasm_std::{operators::Operators, voting::Vote};
    use cosmwasm_std::{Addr, HexBinary, Uint128, Uint256};
    use ethers::{
        abi::{encode, Token},
        contract::EthEvent,
        types::{Log, TransactionReceipt, H256},
    };
    use evm_gateway::{
        i_axelar_amplifier_gateway::{ContractCallFilter, SignersRotatedFilter},
        WeightedSigner, WeightedSigners,
    };
    use multisig::{key::PublicKey, msg::Signer, verifier_set::VerifierSet};

    use super::{verify_message, verify_worker_set};
    use crate::{
        handlers::{evm_verify_msg::Message, evm_verify_verifier_set::VerifierSetConfirmation},
        types::{EVMAddress, Hash},
    };

    #[test]
    fn should_not_verify_worker_set_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut worker_set) =
            get_matching_worker_set_and_tx_receipt();

        worker_set.tx_id = Hash::random();
        assert_eq!(
            verify_worker_set(&gateway_address, &tx_receipt, &worker_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_worker_set_if_tx_failed() {
        let (gateway_address, mut tx_receipt, worker_set) =
            get_matching_worker_set_and_tx_receipt();

        tx_receipt.status = Some(0u64.into());
        assert_eq!(
            verify_worker_set(&gateway_address, &tx_receipt, &worker_set),
            Vote::FailedOnChain
        );
    }

    #[test]
    fn should_not_verify_worker_set_if_gateway_address_does_not_match() {
        let (_, tx_receipt, worker_set) = get_matching_worker_set_and_tx_receipt();

        let gateway_address = EVMAddress::random();
        assert_eq!(
            verify_worker_set(&gateway_address, &tx_receipt, &worker_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_worker_set_if_log_index_does_not_match() {
        let (gateway_address, tx_receipt, mut worker_set) =
            get_matching_worker_set_and_tx_receipt();

        worker_set.event_index = 0;
        assert_eq!(
            verify_worker_set(&gateway_address, &tx_receipt, &worker_set),
            Vote::NotFound
        );
        worker_set.event_index = 2;
        assert_eq!(
            verify_worker_set(&gateway_address, &tx_receipt, &worker_set),
            Vote::NotFound
        );
        worker_set.event_index = 3;
        assert_eq!(
            verify_worker_set(&gateway_address, &tx_receipt, &worker_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_worker_set_if_worker_set_does_not_match() {
        let (gateway_address, tx_receipt, mut worker_set) =
            get_matching_worker_set_and_tx_receipt();

        worker_set.verifier_set.threshold = Uint128::from(50u64);
        assert_eq!(
            verify_worker_set(&gateway_address, &tx_receipt, &worker_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_worker_set_if_correct() {
        let (gateway_address, tx_receipt, worker_set) = get_matching_worker_set_and_tx_receipt();

        assert_eq!(
            verify_worker_set(&gateway_address, &tx_receipt, &worker_set),
            Vote::SucceededOnChain
        );
    }

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.tx_id = Hash::random();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_tx_failed() {
        let (gateway_address, mut tx_receipt, msg) = get_matching_msg_and_tx_receipt();

        tx_receipt.status = Some(0u64.into());
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::FailedOnChain
        );
    }

    #[test]
    fn should_not_verify_msg_if_gateway_address_does_not_match() {
        let (_, tx_receipt, msg) = get_matching_msg_and_tx_receipt();

        let gateway_address = EVMAddress::random();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_log_index_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.event_index = 0;
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
        msg.event_index = 2;
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
        msg.event_index = 3;
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_msg_if_msg_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_receipt();

        msg.source_address = EVMAddress::random();
        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx_receipt, msg) = get_matching_msg_and_tx_receipt();

        assert_eq!(
            verify_message(&gateway_address, &tx_receipt, &msg),
            Vote::SucceededOnChain
        );
    }

    pub fn new_verifier_set() -> VerifierSet {
        let signers = vec![
            Signer {
                address: Addr::unchecked("axelarvaloper1x86a8prx97ekkqej2x636utrdu23y8wupp9gk5"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "03d123ce370b163acd576be0e32e436bb7e63262769881d35fa3573943bf6c6f81",
                    )
                    .unwrap(),
                ),
            },
            Signer {
                address: Addr::unchecked("axelarvaloper1ff675m593vve8yh82lzhdnqfpu7m23cxstr6h4"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "03c6ddb0fcee7b528da1ef3c9eed8d51eeacd7cc28a8baa25c33037c5562faa6e4",
                    )
                    .unwrap(),
                ),
            },
            Signer {
                address: Addr::unchecked("axelarvaloper12cwre2gdhyytc3p97z9autzg27hmu4gfzz4rxc"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "0274b5d2a4c55d7edbbf9cc210c4d25adbb6194d6b444816235c82984bee518255",
                    )
                    .unwrap(),
                ),
            },
            Signer {
                address: Addr::unchecked("axelarvaloper1vs9rdplntrf7ceqdkznjmanrr59qcpjq6le0yw"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "02a670f57de55b8b39b4cb051e178ca8fb3fe3a78cdde7f8238baf5e6ce1893185",
                    )
                    .unwrap(),
                ),
            },
            Signer {
                address: Addr::unchecked("axelarvaloper1hz0slkejw96dukw87fztjkvwjdpcu20jewg6mw"),
                weight: Uint128::from(10u128),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "028584592624e742ba154c02df4c0b06e4e8a957ba081083ea9fe5309492aa6c7b",
                    )
                    .unwrap(),
                ),
            },
        ];

        let mut btree_signers = BTreeMap::new();
        for signer in signers {
            btree_signers.insert(signer.address.clone().to_string(), signer);
        }

        VerifierSet {
            signers: btree_signers,
            threshold: Uint128::from(30u128),
            created_at: 1,
        }
    }

    fn get_matching_worker_set_and_tx_receipt(
    ) -> (EVMAddress, TransactionReceipt, VerifierSetConfirmation) {
        let tx_id = Hash::random();
        let log_index = 1;
        let gateway_address = EVMAddress::random();

        let verifier_set = new_verifier_set();

        let verifier_set = VerifierSetConfirmation {
            tx_id,
            event_index: log_index,
            verifier_set,
        };

        let weighted_signers = WeightedSigners::try_from(&verifier_set.verifier_set).unwrap();

        let log = Log {
            transaction_hash: Some(tx_id),
            log_index: Some(log_index.into()),
            address: gateway_address,
            topics: vec![
                SignersRotatedFilter::signature(),
                H256::from_low_u64_be(1),
                weighted_signers.hash().into(),
            ],
            data: encode(&[Token::Bytes(weighted_signers.abi_encode())]).into(),
            ..Default::default()
        };

        let tx_receipt = TransactionReceipt {
            transaction_hash: tx_id,
            status: Some(1u64.into()),
            logs: vec![Log::default(), log, Log::default()],
            ..Default::default()
        };

        (gateway_address, tx_receipt, verifier_set)
    }

    fn get_matching_msg_and_tx_receipt() -> (EVMAddress, TransactionReceipt, Message) {
        let tx_id = Hash::random();
        let log_index = 1;
        let gateway_address = EVMAddress::random();

        let msg = Message {
            tx_id,
            event_index: log_index,
            source_address: "0xd48e199950589a4336e4dc43bd2c72ba0c0baa86"
                .parse()
                .unwrap(),
            destination_chain: "ethereum-2".parse().unwrap(),
            destination_address: "0xb9845f9247a85Ee592273a79605f34E8607d7e75".into(),
            payload_hash: "0x9fcef596d62dca8e51b6ba3414901947c0e6821d4483b2f3327ce87c2d4e662e"
                .parse()
                .unwrap(),
        };
        let log = Log{
            transaction_hash: Some(tx_id),
            log_index: Some(log_index.into()),
            address: gateway_address,
            topics: vec![
                ContractCallFilter::signature(),
                "0x000000000000000000000000d48e199950589a4336e4dc43bd2c72ba0c0baa86".parse().unwrap(),
                "0x9fcef596d62dca8e51b6ba3414901947c0e6821d4483b2f3327ce87c2d4e662e".parse().unwrap(),
            ],
            data : "0x000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000a657468657265756d2d3200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a3078623938343566393234376138354565353932323733613739363035663334453836303764376537350000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066275666665720000000000000000000000000000000000000000000000000000".parse().unwrap(),
            ..Default::default()
        };
        let tx_receipt = TransactionReceipt {
            transaction_hash: tx_id,
            status: Some(1u64.into()),
            logs: vec![Log::default(), log, Log::default()],
            ..Default::default()
        };

        (gateway_address, tx_receipt, msg)
    }
}
