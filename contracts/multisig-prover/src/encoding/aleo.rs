use aleo_gateway_types::Message;
use aleo_gateway_types::PayloadDigest;
use aleo_gmp_types::aleo_struct::AxelarToLeo as _;
use aleo_gmp_types::multisig_prover::ExecuteSignersRotation;
use aleo_gmp_types::multisig_prover::Proof;
use aleo_gmp_types::utils::ToBytesExt;
use aleo_network_config::network::NetworkConfig;
use axelar_wasm_std::hash::Hash;
use cosmwasm_std::to_json_binary;
use cosmwasm_std::HexBinary;
use error_stack::{Result, ResultExt};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use plaintext_trait::ToPlaintext as _;
use snarkvm_cosmwasm::console::program::Network;
use snarkvm_cosmwasm::prelude::{CanaryV0, Group, MainnetV0, Plaintext, TestnetV0, ToBits as _};
use thiserror::Error;

use crate::error::ContractError;
use crate::payload::Payload;

// Constants for message chunking - these values are determined by `gateway_backend.aleo` program
const MESSAGES_PER_CHUNK: usize = 24;
const MESSAGE_CHUNKS: usize = 2;
const TOTAL_MESSAGE_CAPACITY: usize = MESSAGES_PER_CHUNK * MESSAGE_CHUNKS;

#[derive(Error, Debug)]
enum AleoEncodingError {
    #[error("Failed to hash messages to group: {0}")]
    MessagePayloadHashingFailed(String),
    #[error("Invalid domain separator format")]
    InvalidDomainSeparator,
    #[error("Failed to create payload digest plaintext: {0}")]
    PayloadDigestPlaintextCreationFailed(String),
    #[error("Failed to hash payload digest to group: {0}")]
    PayloadDigestHashFailed(String),
}

macro_rules! dispatch_by_network {
    ($network:expr, $func:ident, $($args:expr),*) => {
        match $network {
            NetworkConfig::TestnetV0 => $func::<TestnetV0>($($args),*),
            NetworkConfig::MainnetV0 => $func::<MainnetV0>($($args),*),
            NetworkConfig::CanaryV0 => $func::<CanaryV0>($($args),*),
        }
    };
}

/// Computes a cryptographic digest for a payload that can be signed by validators.
///
/// This function creates a standardized hash that represents the combination of:
/// - A domain separator (for replay protection across different contexts)
/// - The current verifier set (validators who can sign)
/// - The actual payload data (either messages or a new verifier set)
///
/// The digest is computed using Aleo's BHP256 hash function and follows the
/// [`PayloadDigest`] structure format expected by the Aleo network.
///
/// # Arguments
///
/// * `network` - The Aleo network configuration (TestnetV0, MainnetV0, or CanaryV0)
/// * `domain_separator` - A 32-byte value
/// * `verifier_set` - The current set of validators and their weights/signatures
/// * `payload` - The data to be hashed, either a collection of messages or a new verifier set
///
/// # Returns
///
/// Returns a 32-byte hash that validators can sign to approve the payload.
///
/// # Errors
///
/// * [`ContractError::InvalidDomainSeparator`] - If the domain separator cannot be parsed
/// * [`ContractError::InvalidVerifierSet`] - If the verifier set cannot be converted to Aleo format
/// * [`ContractError::InvalidMessage`] - If messages cannot be processed or hashed
/// * [`ContractError::CreatePayloadDigestFailed`] - If the final digest creation fails
pub fn payload_digest(
    network: &NetworkConfig,
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    dispatch_by_network!(
        network,
        payload_digest_inner,
        domain_separator,
        verifier_set,
        payload
    )
}

/// The relayer will use this data to submit the payload to the contract.
///
/// The encoded data returned from this function will be translated by the relayer
/// to the format that the Aleo program expects.
///
/// This function covers two cases:
/// 1. When the payload is a set of messages.
/// 2. When the payload is a new verifier set.
///
/// In the first case, the function encodes the messages along with the proof.
/// The execute data is as follows:
/// ExecuteData {
///     proof: Proof {
///         weighted_signers: WeightedSigners {
///             signers: Vec<WeightedSigner>,
///             quorum: u128,
///             nonce: u64,
///         }
///         signatures: Vec<signature>,
///     }
///     message: Vec<router_api::Message>,
/// }
///
/// Aleo is expecting specific number of elements, and the relayer is responsible
/// to transform the ExecuteData to the ApproveMessagesInputs struct as expected.
///
/// The execute data as expected by the Aleo GMP program are as follows:
///
/// struct ApproveMessagesInputs {
///     weighted_signers: WeightedSigners,
///     signatures: [[signature; 14]; 2],
///     messages: [[group; 24]; 2],
/// }
///
/// In the second case, the function encodes the new verifier set along with the proof.
/// The execute data is as follows:
/// ExecuteSignersRotation {
///     proof: Proof {
///         weighted_signers: WeightedSigners {
///         signers: Vec<WeightedSigner>,
///         quorum: u128,
///         nonce: u64,
///     },
///     new_verifier_set: VerifierSet,
/// }
///
/// The execute data as expected by the Aleo GMP program are as follows:
/// struct RotateSignersInputs {
///    weighted_signers: WeightedSigners,
///    signatures: [[signature; 14]; 2],
///    payload: VerifierSet,
/// }
pub fn encode_execute_data(
    network: &NetworkConfig,
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    dispatch_by_network!(
        network,
        encode_execute_data_inner,
        verifier_set,
        signatures,
        payload
    )
}

// Use this function to compute the default message hash
fn default_message_hash<N: Network>() -> Group<N> {
    let message = Message::<N>::default();
    let plaintext: Plaintext<N> = Plaintext::try_from(&message).unwrap();
    N::hash_to_group_bhp256(&plaintext.to_bits_le()).unwrap()
}

/// Hashes a collection of messages into a single group element
///
/// This function:
/// 1. Converts messages to Aleo format and hashes them
/// 2. Pads with default hashes to reach the required capacity
/// 3. Organizes into the chunk structure expected by Aleo programs
/// 4. Computes final hash of the structured data
fn hash_messages<N: Network>(messages: &[router_api::Message]) -> Result<Group<N>, ContractError> {
    let default_message_hash = default_message_hash::<N>();

    let aleo_messages = messages.iter().filter_map(|m| {
        let aleo_gmp_message = m.to_leo().ok()?;
        aleo_gmp_types::utils::bhp(&aleo_gmp_message).ok()
    });

    let mut groups = aleo_messages
        .chain(std::iter::repeat(default_message_hash))
        .take(TOTAL_MESSAGE_CAPACITY);

    // It's safe to unwrap because iterator is infinite due to repeat()
    let messages: [[Group<N>; MESSAGES_PER_CHUNK]; MESSAGE_CHUNKS] =
        std::array::from_fn(|_| std::array::from_fn(|_| groups.next().unwrap()));

    let messages_plaintext = messages.to_plaintext();

    N::hash_to_group_bhp256(&messages_plaintext.to_bits_le())
        .map_err(|e| AleoEncodingError::MessagePayloadHashingFailed(e.to_string()))
        .change_context_lazy(|| ContractError::InvalidMessage)
}

/// Parses a 32-byte domain separator into two u128 values
///
/// The domain separator is split into two 128-bit values in little-endian format
/// as required by the Aleo PayloadDigest structure.
fn parse_domain_separator(domain_separator: &[u8; 32]) -> Result<[u128; 2], AleoEncodingError> {
    let first_half = domain_separator[0..16]
        .try_into()
        .map_err(|_| AleoEncodingError::InvalidDomainSeparator)?;
    let second_half = domain_separator[16..32]
        .try_into()
        .map_err(|_| AleoEncodingError::InvalidDomainSeparator)?;

    Ok([
        u128::from_le_bytes(first_half),
        u128::from_le_bytes(second_half),
    ])
}

/// Internal implementation of payload digest computation
///
/// This function is generic over the network type and performs the actual
/// digest computation after network-specific dispatching.
fn payload_digest_inner<N: Network>(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    use aleo_gmp_types::aleo_struct::AxelarToLeo;

    let data_hash = match payload {
        Payload::Messages(messages) => hash_messages::<N>(messages)?,
        Payload::VerifierSet(verifier_set) => verifier_set
            .to_leo()
            .and_then(|leo_verifier_set| aleo_gmp_types::utils::bhp(&leo_verifier_set))
            .change_context_lazy(|| ContractError::InvalidVerifierSet)?,
    };

    let domain_separator = parse_domain_separator(domain_separator).change_context_lazy(|| {
        ContractError::CreatePayloadDigestFailed
    })?;
    let signer = verifier_set
        .to_leo()
        .change_context_lazy(|| ContractError::InvalidVerifierSet)?;

    let payload_digest = PayloadDigest {
        domain_separator,
        signer,
        data_hash,
    };

    let payload_digest_plaintext = Plaintext::try_from(&payload_digest)
        .map_err(|e| AleoEncodingError::PayloadDigestPlaintextCreationFailed(e.to_string()))
        .change_context_lazy(|| ContractError::CreatePayloadDigestFailed)?;

    let payload_digest_hash = N::hash_to_group_bhp256(&payload_digest_plaintext.to_bits_le())
        .map_err(|e| AleoEncodingError::PayloadDigestHashFailed(e.to_string()))
        .change_context_lazy(|| ContractError::CreatePayloadDigestFailed)?;

    let hash: Hash = payload_digest_hash
        .to_bytes_le_array()
        .change_context_lazy(|| ContractError::CreatePayloadDigestFailed)?;

    Ok(hash)
}

fn encode_execute_data_inner<N: Network>(
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let binary = match payload {
        Payload::Messages(messages) => {
            let proof = Proof::<N>::new(verifier_set, signatures)
                .change_context_lazy(|| ContractError::Proof)?;
            let expected_message_count = messages.len();
            let messages: Vec<Message<N>> =
                messages.iter().filter_map(|m| m.to_leo().ok()).collect();

            error_stack::ensure!(
                expected_message_count == messages.len(),
                ContractError::InvalidMessage
            );

            let execute_data = aleo_gmp_types::multisig_prover::ExecuteData {
                proof: proof.into(),
                messages,
            };

            to_json_binary(&execute_data)
                .change_context_lazy(|| ContractError::SerializeProofFailed)?
        }
        Payload::VerifierSet(new_verifier_set) => {
            let execute_signers_rotation = ExecuteSignersRotation::<N> {
                proof: Proof::<N>::new(verifier_set, signatures)
                    .change_context_lazy(|| ContractError::Proof)?,
                new_verifier_set: new_verifier_set
                    .to_leo()
                    .change_context_lazy(|| ContractError::InvalidVerifierSet)?,
            };

            to_json_binary(&execute_signers_rotation)
                .change_context_lazy(|| ContractError::SerializeProofFailed)?
        }
    };

    Ok(HexBinary::from(binary))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_wasm_std::Participant;
    use cosmwasm_std::Addr;
    use multisig::key::PublicKey;
    use multisig::msg::Signer;
    use router_api::ChainNameRaw;
    use snarkos_account::Account;
    use snarkvm::prelude::{
        Address, FromBytes as _, Literal, PrivateKey, ToBytes, ToFields, Value,
    };

    use super::*;

    fn new_verifier_set() -> VerifierSet {
        // APrivateKey1zkpGiDEvxPujW3BtvU9J3DYbzDAqnYXKjVTQsxcAmxqgcEq
        // AViewKey1fYjUQK5MrZywnhnqYyTgF2MgMGhWpWxj686dfE9pPPZD
        // aleo1wps7pkq6x02mfke684t0wehawykjmvev9suuz3l4dwteqswg9sgqe7xhw9
        let aleo_address: Address<CurrentNetwork> =
            Address::from_str("aleo1wps7pkq6x02mfke684t0wehawykjmvev9suuz3l4dwteqswg9sgqe7xhw9")
                .expect("Failed to parse Aleo address");

        VerifierSet::new(
            vec![(
                Participant {
                    address: Addr::unchecked("axelar1ckguw8l9peg6sykx30cy35t6l0wpfu23xycme7"),
                    weight: 1.try_into().expect("Failed to convert weight"),
                },
                PublicKey::AleoSchnorr(HexBinary::from(
                    aleo_address
                        .to_bytes_le()
                        .expect("Failed to convert address to bytes"),
                )),
            )],
            1u128.into(),
            4860541,
        )
    }

    fn current_verifier_set() -> VerifierSet {
        let aleo_address: Address<CurrentNetwork> =
            Address::from_str("aleo1v7mmux8wkue8zmuxdfks03rh85qchfmms9fkpflgs4dt87n4jy9s8nzfss")
                .expect("Failed to parse Aleo address");

        VerifierSet::new(
            vec![(
                Participant {
                    address: Addr::unchecked("axelar1ckguw8l9peg6sykx30cy35t6l0wpfu23xycme7"),
                    weight: 1.try_into().expect("Failed to convert weight"),
                },
                PublicKey::AleoSchnorr(HexBinary::from(
                    aleo_address
                        .to_bytes_le()
                        .expect("Failed to convert address to bytes"),
                )),
            )],
            1u128.into(),
            4860541,
        )
    }

    fn message() -> router_api::Message {
        router_api::Message {
            cc_id: router_api::CrossChainId {
                source_chain: ChainNameRaw::from_str("aleo-2").expect("Failed to parse chain name"),
                message_id: "au1h9zxxrshyratfx0g0p5w8myqxk3ydfyxc948jysk0nxcna59ssqq0n3n3y"
                    .parse()
                    .expect("Failed to parse message id"),
            },
            source_address: "aleo10fmsqwh059uqm74x6t6zgj93wfxtep0avevcxz0n4w9uawymkv9s7whsau"
                .parse()
                .expect("Failed to parse source address"),
            destination_chain: "aleo-2".parse().expect("Failed to parse chain name"),
            destination_address: "foo.aleo"
                .parse()
                .expect("Failed to parse destination address"),
            payload_hash: [
                0xa4, 0x32, 0xdc, 0x98, 0x3d, 0xfe, 0x6f, 0xc4, 0x8b, 0xb4, 0x7a, 0x90, 0x91, 0x54,
                0x65, 0xd9, 0xc8, 0x18, 0x5b, 0x1c, 0x2a, 0xea, 0x5c, 0x87, 0xf8, 0x58, 0x18, 0xcb,
                0xa3, 0x50, 0x51, 0xc6,
            ],
        }
    }

    type CurrentNetwork = snarkvm::prelude::TestnetV0;

    // The bellow comments represent the public and private keys of the signer.
    // They are useful for manually verifying the function.
    // APrivateKey1zkpFMDCJZbRdcBcjnqjRqCrhcWFf4L9FRRSgbLpS6D47Cmo
    // aleo1v7mmux8wkue8zmuxdfks03rh85qchfmms9fkpflgs4dt87n4jy9s8nzfss
    fn aleo_sig<N: Network>(digest: [u8; 32], private_key: PrivateKey<N>) -> SignerWithSig {
        let group_hash =
            Group::<N>::from_bytes_le(&digest).expect("Failed to convert digest to group");
        let value_hash = Value::from(Literal::Group(group_hash));

        let vlaue_hash_fields = value_hash
            .to_fields()
            .expect("Failed to convert value to fields");
        let aleo_account = Account::try_from(private_key).expect("Failed to create Aleo account");
        let signature = aleo_account
            .sign(&vlaue_hash_fields, &mut rand::thread_rng())
            .expect("Failed to sign digest");

        let encoded_signature: HexBinary = signature
            .to_bytes_le()
            .expect("Failed to encode signature")
            .into();

        let verify_key: Address<N> = aleo_account.address();
        let verify_key_encoded = verify_key
            .to_bytes_le()
            .expect("Failed to encode verify key")
            .into();

        let signer = Signer {
            address: Addr::unchecked("aleo-validator".to_string()),
            weight: 1u128.into(),
            pub_key: PublicKey::AleoSchnorr(verify_key_encoded),
        };

        let signature = multisig::key::Signature::AleoSchnorr(encoded_signature);

        SignerWithSig { signer, signature }
    }

    #[test]
    fn aleo_execute_data_with_signers() {
        let domain_separator = [
            105u8, 115u8, 199u8, 41u8, 53u8, 96u8, 68u8, 100u8, 178u8, 136u8, 39u8, 20u8, 27u8,
            10u8, 70u8, 58u8, 248u8, 227u8, 72u8, 118u8, 22u8, 222u8, 105u8, 197u8, 170u8, 12u8,
            120u8, 83u8, 146u8, 201u8, 251u8, 159u8,
        ];

        let new_verifier_set = new_verifier_set();
        let verifier_set = current_verifier_set();
        let network = NetworkConfig::TestnetV0;
        let digest = payload_digest(
            &network,
            &domain_separator,
            &verifier_set,
            &Payload::VerifierSet(new_verifier_set.clone()),
        )
        .expect("Failed to compute payload digest");

        let private_key =
            PrivateKey::from_str("APrivateKey1zkpFMDCJZbRdcBcjnqjRqCrhcWFf4L9FRRSgbLpS6D47Cmo")
                .expect("Failed to parse private key");
        let signed_digest = aleo_sig::<CurrentNetwork>(digest, private_key);
        let execute_data = encode_execute_data(
            &network,
            &verifier_set,
            vec![signed_digest],
            &Payload::VerifierSet(new_verifier_set),
        )
        .expect("Failed to encode execute data");

        println!("Execute data: {}", execute_data);

        let transformed_signers_rotation_proof =
            aleo_utils::axelar_proof_transformation::transformed_signers_rotation_proof::<
                CurrentNetwork,
            >(execute_data.as_slice())
            .expect("Failed to transform proof");

        let validated = aleo_utils::axelar_proof_transformation::validate_proof2::<CurrentNetwork>(
            &transformed_signers_rotation_proof,
        )
        .expect("Failed to validate proof");

        assert!(validated);
    }

    #[test]
    fn aleo_execute_data_with_messages() {
        let domain_separator = [
            105u8, 115u8, 199u8, 41u8, 53u8, 96u8, 68u8, 100u8, 178u8, 136u8, 39u8, 20u8, 27u8,
            10u8, 70u8, 58u8, 248u8, 227u8, 72u8, 118u8, 22u8, 222u8, 105u8, 197u8, 170u8, 12u8,
            120u8, 83u8, 146u8, 201u8, 251u8, 159u8,
        ];

        let aleo_address: Address<CurrentNetwork> =
            Address::from_str("aleo1v7mmux8wkue8zmuxdfks03rh85qchfmms9fkpflgs4dt87n4jy9s8nzfss")
                .expect("Failed to parse Aleo address");

        let verifier_set = VerifierSet::new(
            vec![(
                Participant {
                    address: Addr::unchecked("axelar1ckguw8l9peg6sykx30cy35t6l0wpfu23xycme7"),
                    weight: 1.try_into().expect("Failed to convert weight"),
                },
                PublicKey::AleoSchnorr(HexBinary::from(
                    aleo_address
                        .to_bytes_le()
                        .expect("Failed to convert address to bytes"),
                )),
            )],
            1u128.into(),
            4860541,
        );

        let network = NetworkConfig::TestnetV0;
        let digest = payload_digest(
            &network,
            &domain_separator,
            &verifier_set,
            &Payload::Messages(vec![message()]),
        )
        .expect("Failed to compute payload digest");

        let private_key =
            PrivateKey::from_str("APrivateKey1zkpFMDCJZbRdcBcjnqjRqCrhcWFf4L9FRRSgbLpS6D47Cmo")
                .expect("Failed to parse private key");
        let signed_digest = aleo_sig::<CurrentNetwork>(digest, private_key);
        let execute_data = encode_execute_data(
            &network,
            &verifier_set,
            vec![signed_digest],
            &Payload::Messages(vec![message()]),
        )
        .expect("Failed to encode execute data");

        let transformed_proof = aleo_utils::axelar_proof_transformation::transform_proof::<
            CurrentNetwork,
        >(execute_data.as_slice())
        .expect("Failed to transform proof");

        let validated = aleo_utils::axelar_proof_transformation::validate_proof::<CurrentNetwork>(
            &transformed_proof,
        )
        .expect("Failed to validate proof");

        assert!(validated);
    }
}
