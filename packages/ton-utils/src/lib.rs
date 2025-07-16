use std::collections::HashMap;
use std::result::Result;
use std::str::FromStr;
use std::sync::Arc;

use axelar_wasm_std::hash::Hash;
use multisig::key::{PublicKey, Signature};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use router_api::Message;
use sha3::{Digest, Keccak256};
use tonlib_core::cell::{Cell, CellBuilder, CellParser, TonCellError};
use tonlib_core::tlb_types::traits::TLBObject;
use tonlib_core::types::TonAddressParseError;
use tonlib_core::TonAddress;

const OP_APPROVE_MESSAGES: usize = 0x00000028;
const OP_START_SIGNER_ROTATION: usize = 0x00000014;
const BYTES_PER_CELL: usize = 96;
const THRESHOLD_BITS: usize = 128;
const NONCE_BITS: usize = 256;
const DICTIONARY_KEY_BITS: usize = 16;
const OPCODE_BITS: usize = 32;
const PAYLOAD_HASH_BITS: usize = 256;
const BITS_PER_BYTE: usize = 8;
const SIGNATURE_BITS: usize = 512;
const SIGNATURE_BYTES: usize = SIGNATURE_BITS / BITS_PER_BYTE;
const SIGNER_PUBKEY_BITS: usize = 256;
const SIGNER_PUBKEY_BYTES: usize = SIGNER_PUBKEY_BITS / BITS_PER_BYTE;

/// Converts a byte buffer into a chain of TON cells.
///
/// This function is a  wrapper around `build_cell_chain`,
/// initiating the recursive construction of a cell chain.
/// The buffer is segmented into chunks, each stored in a separate cell with
/// references to subsequent cells as needed.
///
/// # Parameters
/// - `buffer`: A `Vec<u8>` representing the byte data to be encoded into the cell chain.
///
fn buffer_to_cell(buffer: Vec<u8>) -> Result<Cell, TonCellError> {
    build_cell_chain(0, buffer)
}

#[allow(clippy::arithmetic_side_effects)]
fn build_cell_chain(start_index: usize, buffer: Vec<u8>) -> Result<Cell, TonCellError> {
    let mut builder = CellBuilder::new();
    let end_index = std::cmp::min(start_index + BYTES_PER_CELL, buffer.len());

    // Store bytes in the current cell
    for byte in buffer.iter().take(end_index).skip(start_index) {
        builder.store_uint(BITS_PER_BYTE, &BigUint::from(*byte))?;
    }

    // If there are more bytes, create a reference to the next cell
    if end_index < buffer.len() {
        let next_cell = build_cell_chain(end_index, buffer)?;
        builder.store_reference(&Arc::new(next_cell))?;
    }

    builder.build()
}

/// A data structure representing a set of weighted signers and an associated signing threshold.
///
/// `WeightedSigners` encapsulates a dictionary of individual signers, each with an associated weight
/// and signature, along with a collective threshold and a nonce.
///
/// # Fields
/// - `dict`: A mapping from signer index (`u16`) to `WeightedSigner`, containing public key, weight, and signature.
/// - `threshold`: The minimum cumulative weight required for the signatures to be considered valid.
/// - `nonce`: A value representing the creation time or unique context of the signer set (derived from `VerifierSet::created_at`).

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightedSigners {
    dict: HashMap<u16, WeightedSigner>,
    threshold: u128,
    nonce: u128,
}

/// Helper function to write a WeightedSigner to a key/value dict cell
fn val_writer_weighted_signer(
    builder: &mut CellBuilder,
    val: WeightedSigner,
) -> Result<(), TonCellError> {
    builder.store_slice(&val.to_bytes())?;
    Ok(())
}

impl WeightedSigners {
    /// Constructs a new `WeightedSigners` instance from a verifier set and a vector of signer signatures.
    ///
    /// This function converts the provided `VerifierSet` into an internal signer dictionary,
    /// verifying that all signers and signatures use the Ed25519 scheme.
    ///
    /// # Parameters
    /// - `set`: A reference to a `VerifierSet` containing public keys and weight information.
    /// - `signatures`: A vector of `SignerWithSig`, where each entry corresponds to a signer in `set`.
    pub fn new(set: &VerifierSet, signatures: Vec<SignerWithSig>) -> Result<Self, String> {
        if set.signers.len() != signatures.len() {
            return Err("Require exactly one signature for each signer".to_string());
        }

        let nonce = set.created_at as u128;
        let threshold = set.threshold.into();

        // todo: convert set.signers to HashMap<u16, WeightedSigner>,
        let maybe_dict: Result<HashMap<u16, WeightedSigner>, String> = set
            .signers
            .values()
            .enumerate()
            .map(|(i, signer)| -> Result<(u16, WeightedSigner), String> {
                let pub_key_bytes = match &signer.pub_key {
                    PublicKey::Ed25519(key) => key.as_slice().try_into().unwrap(),
                    _ => return Err("Only Ed25519 public keys are supported in Ton".to_string()),
                };
                let signature_bytes = match &signatures[i].signature {
                    Signature::Ed25519(sig) => sig.as_slice().try_into().unwrap(),
                    _ => return Err("Only Ed25519 signatures are supported in Ton".to_string()),
                };
                Ok((
                    u16::try_from(i).unwrap(),
                    WeightedSigner::new(pub_key_bytes, signer.weight.u128(), signature_bytes),
                ))
            })
            .collect::<Result<HashMap<_, _>, _>>();

        match maybe_dict {
            Ok(dict) => Ok(WeightedSigners {
                dict,
                threshold,
                nonce,
            }),
            Err(e) => Err(e),
        }
    }

    /// Serializes the `WeightedSigners` into a TON cell.
    ///
    /// This method encodes the dictionary of weighted signers, the threshold, and the nonce
    /// into a `Cell` structure.
    pub fn to_cell(&self) -> Result<Cell, TonCellError> {
        let mut builder = CellBuilder::new();
        let nonce = BigUint::from(self.nonce);
        let threshold = BigUint::from(self.threshold);

        builder.store_dict(
            DICTIONARY_KEY_BITS,
            val_writer_weighted_signer,
            self.dict.clone(),
        )?;
        builder.store_uint(THRESHOLD_BITS, &threshold)?;
        builder.store_uint(NONCE_BITS, &nonce)?;
        let dict_cell = builder.build()?;

        Ok(dict_cell)
    }
}

/// Represents an individual signer with an associated public key, signature, and weight.
///
/// This structure is used in the context of weighted multisignature schemes, where
/// each signer contributes a certain weight toward meeting a collective signing threshold.
///
/// # Fields
/// - `signer`: The Ed25519 public key of the signer, represented as a fixed-size byte array.
/// - `weight`: The numerical weight associated with the signer, as used in the threshold validation.
/// - `signature`: The signer's Ed25519 signature, represented as a fixed-size byte array.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct WeightedSigner {
    signer: [u8; SIGNER_PUBKEY_BYTES],
    weight: u128,
    signature: [u8; SIGNATURE_BYTES],
}

impl WeightedSigner {
    /// Creates a new `WeightedSigner` instance.
    pub fn new(
        signer: [u8; SIGNER_PUBKEY_BYTES],
        weight: u128,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Self {
        WeightedSigner {
            signer,
            weight,
            signature,
        }
    }

    /// Serializes the `WeightedSigner` into a contiguous byte vector.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.signer);
        bytes.extend_from_slice(&self.weight.to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }
}

/// Attempts to convert a `VerifierSet` into a `WeightedSigners` instance without signatures.
///
/// Each entry in the `VerifierSet` is parsed and transformed into a `WeightedSigner`
/// with a zero-filled signature. Public keys must be of Ed25519 type and 32 bytes in length.
/// Dictionary keys are parsed from `String` to `u16`.
///
/// # Errors
/// Returns an `Err(String)` if:
/// - A dictionary key in the `VerifierSet` cannot be parsed into a `u16`.
/// - A public key is not of type `Ed25519`.
/// - A public key cannot be converted into a `[u8; 32]` array (invalid size).
impl TryFrom<VerifierSet> for WeightedSigners {
    type Error = String;

    fn try_from(verifier_set: VerifierSet) -> Result<Self, Self::Error> {
        let mut dict = HashMap::new();

        for (index_str, signer) in verifier_set.signers {
            let index: u16 = index_str.parse().map_err(|_| "Invalid index key")?;
            let signer_bytes = match signer.pub_key {
                PublicKey::Ed25519(ref hex) => hex.to_vec(),
                _ => return Err("Unsupported public key type".to_string()),
            };

            dict.insert(
                index,
                WeightedSigner {
                    signer: signer_bytes
                        .try_into()
                        .map_err(|_| "Expected 32-byte public key")?,
                    weight: signer.weight.u128(),
                    signature: [0; 64],
                },
            );
        }

        Ok(WeightedSigners {
            dict,
            threshold: verifier_set.threshold.u128(),
            nonce: verifier_set.created_at as u128,
        })
    }
}

/// A trait providing utility methods to extract structured data from a TON cell chain.
///
/// This trait is intended to be the inverse operation of `buffer_to_cell`, enabling
/// the deserialization of data stored across a chain of cells back into its original
/// binary or textual form.
///
/// The trait assumes that the cell chain was constructed using a linear layout,
/// such as from `buffer_to_cell` or `build_cell_chain`, where each cell contains
/// a chunk of raw bytes and a reference to the next cell.
trait CellTo {
    fn cell_to_string(self) -> String;

    fn cell_to_buffer(self) -> Vec<u8>;
}

impl CellTo for Arc<Cell> {
    fn cell_to_buffer(self) -> Vec<u8> {
        let mut current_cell = Some(self);
        let mut u8_vec = vec![];

        while let Some(cell) = current_cell {
            let mut parser = cell.parser();
            for _ in 0..BYTES_PER_CELL {
                let next_byte = match parser.load_uint(8) {
                    Ok(internal) => internal.to_bytes_be()[0],
                    Err(_) => break, // this means we are done
                };
                u8_vec.push(next_byte);
            }
            match parser.next_reference() {
                Ok(r) => current_cell = Some(r),
                _ => break,
            }
        }
        u8_vec
    }

    fn cell_to_string(self) -> String {
        String::from_utf8_lossy(&self.cell_to_buffer()).into()
    }
}

/// Helper function to read the u16 key from a key/value dict cell
fn key_reader_weighted_signer(key: &BigUint) -> Result<u16, TonCellError> {
    Ok(key.to_u16().unwrap())
}

/// Helper function to read the WeightedSigner value from a key/value dict cell
fn val_reader_weighted_signer(parser: &mut CellParser) -> Result<WeightedSigner, TonCellError> {
    let signer_bytes = parser.load_bits(256)?;
    let signer: [u8; 32] = signer_bytes
        .try_into()
        .map_err(|_| TonCellError::InternalError("Failed to convert signer bytes".to_string()))?;

    let weight = parser.load_uint(128)?;
    let weight = weight.to_u128().ok_or(TonCellError::InternalError(
        "Failed to cast to u128".to_string(),
    ))?; // this cannot fail

    let signature_bytes = parser.load_bits(512)?;
    let signature: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        TonCellError::InternalError("Failed to convert signature bytes".to_string())
    })?; // this cannot fail

    Ok(WeightedSigner::new(signer, weight, signature))
}

/// Parses a TON cell representing a rotation log of weighted signers and reconstructs a `WeightedSigners` structure.
///
/// This function is the inverse of the serialization logic performed in `WeightedSigners::to_cell`.
/// It reads a structured cell that encodes a dictionary of signers along with threshold and nonce metadata.
/// The dictionary entries are expected to follow the layout defined by `WeightedSigner`.
///
/// # Cell Format Assumptions
/// The input cell must contain:
/// - A dictionary with 16-bit keys (parsed as `u16`) and values formatted as:
///     - 256-bit public key (Ed25519, `[u8; 32]`)
///     - 128-bit weight (`u128`)
///     - 512-bit signature (Ed25519, `[u8; 64]`)
/// - A 128-bit threshold (`u128`)
/// - A 256-bit nonce (`u128`)
///
/// # Parameters
/// - `cell`: A reference to an `Arc<Cell>` representing the serialized signer log.
///
/// # Returns
/// A `WeightedSigners` instance reconstructed from the cell content, or a wrapped error if parsing fails.
pub fn cell_parse_rotate_signers_log(cell: &Arc<Cell>) -> Result<WeightedSigners, TonCellError> {
    let mut parser = cell.parser();
    let dict = parser.load_dict(16, key_reader_weighted_signer, val_reader_weighted_signer)?;
    let threshold = parser.load_uint(128)?;
    let nonce = parser.load_uint(256)?;

    let derived_weighted_signers = WeightedSigners {
        dict,
        threshold: threshold.to_u128().unwrap(),
        nonce: nonce.to_u128().unwrap(),
    };

    Ok(derived_weighted_signers)
}

/// Parses a TON cell representing a logged cross-chain contract call emitted by the Ton gateway
/// and extracts the relevant metadata and identifiers.
///
/// This function expects the cell to encode references to other cells and inline data
/// describing a cross-chain call. It extracts the destination chain and address (as UTF-8 strings),
/// the payload (ignored here but validated structurally), the source address, and the payload hash.
///
/// # Cell Format Assumptions
/// The input `cell` must contain the following in order:
/// 1. A reference to a cell containing the UTF-8 encoded **destination chain** name.
/// 2. A reference to a cell containing the UTF-8 encoded **destination address**.
/// 3. A reference to a cell containing the raw **payload** (used only to validate structure).
/// 4. An inline TON address representing the **source address**.
/// 5. A 256-bit inline payload hash.
///
/// # Returns
/// On success, returns a tuple containing:
/// - `[u8; 32]`: The 256-bit hash of the payload.
/// - `String`: The destination address string.
/// - `String`: The destination chain name.
/// - `TonAddress`: The source address.
pub fn cell_parse_call_contract_log(
    cell: &Arc<Cell>,
) -> Result<([u8; 32], String, String, TonAddress), TonCellError> {
    let mut parser = cell.parser();
    let destination_chain = parser.next_reference()?;

    let destination_chain = destination_chain.cell_to_string();

    let destination_address = parser.next_reference()?;

    let destination_address = destination_address.cell_to_string();

    let payload = parser.next_reference()?;

    let _ = payload.cell_to_buffer();

    let source_address = parser.load_address()?;

    let payload_hash: [u8; 32] = parser
        .load_bits(256)?
        .try_into()
        .map_err(|_| TonCellError::InternalError("Couldn't load payload hash".to_string()))?;

    Ok((
        payload_hash,
        destination_address,
        destination_chain,
        source_address,
    ))
}

/// Constructs a proof cell from a given verifier set and corresponding signatures, to be sent to the TON gateway.
///
/// This function is responsible for creating a serialized proof cell that contains:
/// - A mapping of signer indices to `WeightedSigner` instances (public key, weight, and signature),
/// - The multisig threshold value,
/// - A nonce representing the creation timestamp of the verifier set.
///
/// The proof is structured as a TON cell and can be used for validation of
/// signed messages in smart contracts or off-chain verification systems.
///
/// # Parameters
/// - `verifier_set`: A reference to the `VerifierSet`, which contains the required
///   multisig parameters (signers, threshold, and timestamp).
/// - `signatures`: A vector of `SignerWithSig`, each of which includes a corresponding
///   Ed25519 signature for a signer in the verifier set.
fn construct_proof(
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
) -> Result<Cell, TonCellError> {
    let maybe_proof = WeightedSigners::new(verifier_set, signatures);
    match maybe_proof {
        Ok(proof) => proof.to_cell(),
        Err(e) => Err(TonCellError::InternalError(e)),
    }
}

/// A wrapper for getting a cell-chain containing a string
fn get_arced_cell(inner: &str) -> Result<Arc<Cell>, TonCellError> {
    Ok(Arc::new(buffer_to_cell(inner.as_bytes().to_vec())?))
}

/// Serializes a `Message` struct into a TON cell.
///
/// The serialized format consists of:
/// - A reference to a cell containing the message ID.
/// - A reference to a cell containing the source chain identifier.
/// - A reference to a cell containing the source address.
/// - A nested cell with:
///   - A reference to a cell containing the destination address.
///   - A reference to a cell containing the destination chain identifier.
/// - A 256-bit payload hash.
///
fn message_to_cell(msg: Message) -> Result<Cell, TonCellError> {
    let mut builder = CellBuilder::new();
    builder.store_reference(&get_arced_cell(&msg.cc_id.message_id)?)?;
    builder.store_reference(&get_arced_cell(msg.cc_id.source_chain.as_ref())?)?;
    builder.store_reference(&get_arced_cell(&msg.source_address)?)?;

    let ton_address_hash_buffer = TonAddress::from_str(&msg.destination_address)
        .map_err(|_| {
            TonCellError::InternalError("Failed to parse Address as TonAddress".to_string())
        })?
        .hash_part
        .to_vec();
    let ton_address_hash_buffer_cell = buffer_to_cell(ton_address_hash_buffer).map_err(|_| {
        TonCellError::InternalError("Failed to transform buffer into chain of cells".to_string())
    })?;

    let mut last_cell_builder = CellBuilder::new();
    last_cell_builder.store_reference(&Arc::new(ton_address_hash_buffer_cell.clone()))?; // problem this should be the Ton address hash!!! .storeRef(bufferToCell(msg.executableAddress.hash))
    last_cell_builder.store_reference(&get_arced_cell(msg.destination_chain.as_ref())?)?;
    let last_cell = last_cell_builder.build()?;

    builder.store_reference(&Arc::new(last_cell))?;
    builder.store_uint(
        PAYLOAD_HASH_BITS,
        &BigUint::from_bytes_be(&msg.payload_hash),
    )?;

    let res = builder.build()?;
    Ok(res)
}

#[derive(Debug)]
struct TonMessages {
    dict: HashMap<u16, Message>,
}

/// Helper function to write the value to a key/value dict cell
fn val_writer_message(builder: &mut CellBuilder, val: Message) -> Result<(), TonCellError> {
    builder.store_reference(&Arc::new(message_to_cell(val).map_err(|_| {
        TonCellError::InternalError("Failed to transform Message into Cell".to_string())
    })?))?;
    Ok(())
}

/// Implements construction and serialization for a collection of `Message` instances
/// to be encoded into a TON cell structure.
impl TonMessages {
    /// Creates a new `TonMessages` instance from a slice of `Message` values.
    fn new(messages: &[Message]) -> Result<Self, TonCellError> {
        if messages.len() > u16::MAX as usize {
            return Err(TonCellError::InternalError("Too many messages".to_string()));
        }
        let msgs_hashmap: HashMap<u16, Message> = messages
            .iter() // Changed from into_iter() to iter()
            .enumerate()
            .map(|(i, msg)| (u16::try_from(i).unwrap(), msg.clone())) // Added clone() since we're borrowing
            .collect();
        Ok(TonMessages { dict: msgs_hashmap })
    }

    /// Serializes the `TonMessages` into a TON cell using a dictionary.
    fn to_cell(&self) -> Result<Cell, TonCellError> {
        let mut builder = CellBuilder::new();

        builder.store_dict(DICTIONARY_KEY_BITS, val_writer_message, self.dict.clone())?;
        let dict_cell = builder.build()?;

        Ok(dict_cell)
    }
}

/// Wrapper to create a TON cell containing a slice of `Message` values.
fn construct_messages(messages: &[Message]) -> Result<Cell, TonCellError> {
    let ton_msgs = TonMessages::new(messages)?;
    ton_msgs.to_cell()
}

/// Constructs a TON cell representing an "approve messages" operation, which includes
/// the verifier set, the signatures and a set of cross-chain messages.
///
/// The resulting cell can be sent to the TON gateway as an internal message.
///
/// # Parameters
/// - `messages`: A borrowed slice of `Message` objects representing cross-chain messages to be approved.
/// - `verifier_set`: A reference to a `VerifierSet` defining the authorized signers and the threshold.
/// - `signatures`: A vector of `SignerWithSig` containing the corresponding cryptographic signatures.
///
pub fn build_approve_messages_body(
    messages: &[Message],
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
) -> Result<Cell, TonCellError> {
    let proof = construct_proof(verifier_set, signatures)?;
    let messages = construct_messages(messages)?;

    let mut builder = CellBuilder::new();
    builder.store_uint(OPCODE_BITS, &BigUint::from(OP_APPROVE_MESSAGES))?;
    builder.store_reference(&Arc::new(proof))?;
    builder.store_reference(&Arc::new(messages))?;

    builder.build()
}

/// Constructs a TON cell representing a "signer rotation" operation, which includes
/// the new verifier set, the current verifier set and the signatures.
///
/// The resulting cell can be sent to the TON gateway as an internal message.
///
/// /// # Parameters
/// - `candidate_set`: A reference to the `VerifierSet` that should replace the current one.
/// - `current_set`: A reference to the existing `VerifierSet`, used to verify the provided signatures.
/// - `signatures`: A vector of `SignerWithSig` containing the signatures by members of `current_set`.
///
pub fn build_signer_rotation_body(
    candidate_set: &VerifierSet,
    current_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
) -> Result<Cell, TonCellError> {
    let proof = construct_proof(current_set, signatures)?;
    let candidate_config_hash = compute_verifier_set_hash(candidate_set)?;
    let candidate_config_hash_cell = buffer_to_cell(candidate_config_hash.to_vec())?;

    let mut builder = CellBuilder::new();
    builder.store_uint(OPCODE_BITS, &BigUint::from(OP_START_SIGNER_ROTATION))?;
    builder.store_reference(&Arc::new(candidate_config_hash_cell))?;
    builder.store_reference(&Arc::new(proof))?;

    builder.build()
}

/// Calculates the hash of given `Message` slice in the same way as the TON gateway.
///
/// # Parameters
/// - `msgs`: A slice of `Message` structures representing the cross-chain messages to hash.
fn compute_data_hash(msgs: &[Message]) -> Result<Hash, TonAddressParseError> {
    let mut concatenated: Vec<u8> = Vec::new();

    for msg in msgs.iter().cloned() {
        let message_id = msg.cc_id.message_id;
        let source_chain = msg.cc_id.source_chain;
        let source_contract_address = msg.source_address;
        let contract_address = msg.destination_address;
        let destination_chain = msg.destination_chain;
        let payload_hash = msg.payload_hash;

        concatenated.extend(message_id.as_bytes());

        concatenated.extend(source_chain.to_string().as_bytes());
        concatenated.extend(source_contract_address.as_bytes());

        let ton_address_hash_buffer = TonAddress::from_str(&contract_address)?.hash_part.to_vec();

        concatenated.extend(ton_address_hash_buffer);
        concatenated.extend(destination_chain.to_string().as_bytes());
        concatenated.extend(payload_hash.as_slice());
    }

    Ok(Keccak256::digest(concatenated).into())
}

/// Calculates the hash of given `VerifierSet` in the same way as the TON gateway.
#[allow(clippy::arithmetic_side_effects)]
fn compute_verifier_set_hash(verifier_set: &VerifierSet) -> Result<Hash, TonCellError> {
    let mut data = Vec::new();
    data.extend(verifier_set.threshold.to_be_bytes());

    // Convert nonce to 256-bit (32 bytes)
    let mut nonce_bytes = [0u8; NONCE_BITS / 8];
    let nonce_be = verifier_set.created_at.to_be_bytes();
    nonce_bytes[NONCE_BITS / 8 - nonce_be.len()..].copy_from_slice(&nonce_be);
    data.extend(nonce_bytes);

    let mut current_hash = Keccak256::digest(&data);

    // Sort the keys lexicographically
    let mut sorted_keys: Vec<&String> = verifier_set.signers.keys().collect();
    sorted_keys.sort();

    for (i, key) in sorted_keys.iter().enumerate() {
        let signer = verifier_set.signers.get(*key).unwrap(); // assert: key in verifier_set.signers since we iterate over the keys

        let mut hasher = Keccak256::new();
        hasher.update(
            u16::try_from(i)
                .map_err(|_| TonCellError::InternalError("Too many signers".to_string()))?
                .to_be_bytes(),
        ); // assert: less than 2^16 = 65536 signers
        hasher.update(&signer.pub_key);
        hasher.update(signer.weight.to_be_bytes());
        hasher.update(current_hash);
        current_hash = hasher.finalize();
    }

    Ok(current_hash.into())
}

/// Calculates the hash of given `Message` slice and `VerifierSet` in the same way as the TON gateway,
/// for use an "approve messages" operation.
pub fn compute_approve_messages_hash(
    msgs: &[Message],
    verifier_set: &VerifierSet,
    domain_separator: &Hash,
) -> Result<Hash, TonCellError> {
    let data_hash = compute_data_hash(msgs)
        .map_err(|_| TonCellError::InternalError("Failed to compute data hash".to_string()))?;
    let signers_hash = compute_verifier_set_hash(verifier_set)?;

    let mut result = Vec::new();
    result.extend(data_hash.to_vec());
    result.extend(signers_hash.to_vec());
    result.extend(domain_separator.to_vec());

    Ok(Keccak256::digest(result).into())
}

/// Calculates the hash of given two `VerifierSet` in the same way as the TON gateway, for use in
/// a "rotate signers" operation.
pub fn compute_signer_rotation_hash(
    candidate_set: &VerifierSet,
    current_set: &VerifierSet,
    domain_separator: &Hash,
) -> Result<Hash, TonCellError> {
    let candidate_set_hash = compute_verifier_set_hash(candidate_set)?;
    let current_set_hash = compute_verifier_set_hash(current_set)?;

    let mut result = Vec::new();

    result.extend(candidate_set_hash.to_vec());
    result.extend(current_set_hash.to_vec());
    result.extend(domain_separator);

    Ok(Keccak256::digest(result).into())
}

// A wrapper to encode a TON `Cell` as a hex string.
pub fn cell_to_boc_hex(cell: Cell) -> Result<String, TonCellError> {
    cell.to_boc_hex(true)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use axelar_wasm_std::{nonempty, Participant};
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use itertools::Itertools;
    use multisig::key::{KeyTyped, Signature};
    use multisig::msg::{Signer, SignerWithSig};
    use multisig::verifier_set::VerifierSet;
    use router_api::{ChainName, ChainNameRaw, CrossChainId, Message};
    use tonlib_core::cell::Cell;
    use tonlib_core::tlb_types::traits::TLBObject;

    use crate::{
        buffer_to_cell, build_signer_rotation_body, cell_to_boc_hex, compute_approve_messages_hash,
        message_to_cell, CellTo, WeightedSigners,
    };

    const LOREM_STR: &str = "Lorem ipsum dolor sit amet ullamco ipsum. Est nulla veniam fugiat ut consectetur mollit ipsum duis nostrud ullamco cupidatat ad Lorem eu incididunt adipisicing laboris nisi. Ad mollit exercitation, culpa aute esse incididunt officia anim sint adipisicing labore anim exercitation aliquip irure id nisi tempor. Ipsum anim dolore sit incididunt ipsum nisi.  Id quis veniam occaecat est ad. Aliquip adipisicing culpa sit esse eiusmod laboris voluptate, sit. Esse amet esse occaecat laboris minim culpa officia ullamco et reprehenderit proident occaecat ullamco ipsum sunt ipsum est quis enim esse veniam est ut. Deserunt fugiat aliqua proident officia enim laboris Lorem qui dolor irure qui.  Excepteur elit est adipisicing ex in commodo eiusmod elit ea minim velit, et id aute voluptate velit fugiat culpa. Ipsum fugiat non in adipisicing eu voluptate fugiat occaecat ex enim consequat consectetur ex in. Magna reprehenderit id nisi sunt pariatur minim officia elit a";
    const LOREM_BOC: &str = "b5ee9c7241020b010003e50001c04c6f72656d20697073756d20646f6c6f722073697420616d657420756c6c616d636f20697073756d2e20457374206e756c6c612076656e69616d2066756769617420757420636f6e7365637465747572206d6f6c6c697420697073756d2064750101c06973206e6f737472756420756c6c616d636f20637570696461746174206164204c6f72656d20657520696e6369646964756e74206164697069736963696e67206c61626f726973206e6973692e204164206d6f6c6c69742065786572636974610201c074696f6e2c2063756c70612061757465206573736520696e6369646964756e74206f66666963696120616e696d2073696e74206164697069736963696e67206c61626f726520616e696d20657865726369746174696f6e20616c6971756970200301c06972757265206964206e6973692074656d706f722e20497073756d20616e696d20646f6c6f72652073697420696e6369646964756e7420697073756d206e6973692e2020496420717569732076656e69616d206f6363616563617420657374200401c061642e20416c6971756970206164697069736963696e672063756c706120736974206573736520656975736d6f64206c61626f72697320766f6c7570746174652c207369742e204573736520616d65742065737365206f63636165636174206c0501c061626f726973206d696e696d2063756c7061206f66666963696120756c6c616d636f20657420726570726568656e64657269742070726f6964656e74206f6363616563617420756c6c616d636f20697073756d2073756e7420697073756d20650601c07374207175697320656e696d20657373652076656e69616d206573742075742e204465736572756e742066756769617420616c697175612070726f6964656e74206f66666963696120656e696d206c61626f726973204c6f72656d20717569200701c0646f6c6f72206972757265207175692e202045786365707465757220656c697420657374206164697069736963696e6720657820696e20636f6d6d6f646f20656975736d6f6420656c6974206561206d696e696d2076656c69742c20657420690801c064206175746520766f6c7570746174652076656c6974206675676961742063756c70612e20497073756d20667567696174206e6f6e20696e206164697069736963696e6720657520766f6c75707461746520667567696174206f6363616563610901c07420657820656e696d20636f6e73657175617420636f6e736563746574757220657820696e2e204d61676e6120726570726568656e6465726974206964206e6973692073756e74207061726961747572206d696e696d206f66666963696120650a000a6c697420619267e790";

    #[test]
    fn should_encode_correctly() {
        let lorem = String::from(LOREM_STR).into_bytes();
        let expected: String = LOREM_BOC.to_string();

        let cell = buffer_to_cell(lorem).unwrap();
        let cell_encoded = cell_to_boc_hex(cell).unwrap();

        assert_eq!(cell_encoded, expected);
    }

    #[test]
    fn should_decode_correctly() {
        let cell = Cell::from_boc_hex(LOREM_BOC).unwrap().to_arc();

        let s = cell.cell_to_string();

        assert_eq!(s, LOREM_STR);
    }

    #[test]
    fn should_encode_and_decode_empty_string() {
        let empty_string = vec![];

        let cell = buffer_to_cell(empty_string.clone()).unwrap();
        let cell_encoded = cell_to_boc_hex(cell).unwrap();

        let cell_decoded = Cell::from_boc_hex(&cell_encoded).unwrap().to_arc();
        let string_decoded = cell_decoded.cell_to_string();

        assert_eq!(string_decoded.as_bytes(), empty_string);
    }

    #[test]
    fn message_to_cell_okay() {
        let msg = Message {
            cc_id: CrossChainId {
                source_chain: ChainNameRaw::try_from("Testchain".to_string()).unwrap(),
                message_id: "Some message".try_into().unwrap(),
            },
            source_address: "from-some-address".to_string().try_into().unwrap(),
            destination_chain: ChainName::try_from("TestChain2".to_string()).unwrap(),
            destination_address:
                "0:4d3e1eb3fef978b01cfc0189d990804f03c922a63c61971963f80f2b1bd1761a"
                    .to_string()
                    .try_into()
                    .unwrap(),
            payload_hash: [0; 32],
        };
        let res = message_to_cell(msg);
        assert!(res.is_ok());
    }

    #[test]
    fn message_to_cell_invalid_ton_address() {
        let msg = Message {
            cc_id: CrossChainId {
                source_chain: ChainNameRaw::try_from("Testchain".to_string()).unwrap(),
                message_id: "Some message".try_into().unwrap(),
            },
            source_address: "0:4d3e1eb3fef978b01cfc0189d990804f03c922a63c61971963f80f2b1bd1761a"
                .to_string()
                .try_into()
                .unwrap(),
            destination_chain: ChainName::try_from("TestChain2".to_string()).unwrap(),
            destination_address: "not-a-ton-address".to_string().try_into().unwrap(),
            payload_hash: [0; 32],
        };
        let res = message_to_cell(msg);
        assert!(res.is_err());
    }

    #[test]
    fn should_reject_conversion_incorrect_key_type() {
        let incorrect_verifier_set = incorrect_key_type_curr_ton_verifier_set();
        let weighted_signers = WeightedSigners::try_from(incorrect_verifier_set);
        assert!(weighted_signers.is_err());
    }

    #[test]
    fn should_compute_correct_approve_messages_hash() {
        let domain_separator = ton_domain_separator();
        let current_set = curr_ton_verifier_set();
        let msgs = ton_messages();

        let digest = compute_approve_messages_hash(&msgs, &current_set, &domain_separator).unwrap();

        assert_eq!(
            hex_encode(digest.to_vec().as_slice()),
            "e8214b369d9f4b11f4f0f7d2c921b56e9a34033e8f7f8599abe819b3cb7de2e0"
        );
    }

    #[test]
    fn should_encode_rotate_signers() {
        let verifier_set = curr_ton_verifier_set();

        let mut new_ton_set = curr_ton_verifier_set();
        new_ton_set.created_at += 1;

        let sigs: Vec<_> = vec![
            "63d43de6b5780ea29849a82b9b616c3a7c8c5332e5a1b34408c2745eabf07e2c7d539134e3480e3b3e1ac689f9fff05047b9bb1ecf1208732cf53a39ae0fe701",
            "e619721e05b552e3090dc4a48624ada4ff91a4a4fbd94e2347f1e9716d95c9f1e43c29c1613838ef7beb2daec16c036d0942cc274d15ea64020c5fd94af94205",
            "9b7265c9660f8dd37e99e6c8e4e5fc020a1f0ddb9d55c3f352e826990af144485903cb41b47d6091f7c753ff5de667414be03bfe6a1d3f06513d949005a3500c",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let encoded_signer_rotation =
            build_signer_rotation_body(&new_ton_set, &verifier_set, signers_with_sigs).unwrap();

        assert_eq!(cell_to_boc_hex(encoded_signer_rotation).unwrap(), "b5ee9c72410208010001c10002080000001401020040ab98abb510250ae97f3834f06829b35e08d6711dd57753b9c16307aadb4e5d5c0161800000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000c0030202ce0405020120060700e1479b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664000000000000000000000000000000019b7265c9660f8dd37e99e6c8e4e5fc020a1f0ddb9d55c3f352e826990af144485903cb41b47d6091f7c753ff5de667414be03bfe6a1d3f06513d949005a3500c800e100e841effcf3842f875c374639d2f02659f9358c26e94357c777219904954c6e0000000000000000000000000000000058f50f79ad5e03a8a6126a0ae6d85b0e9f2314ccb9686cd102309d17aafc1f8b1f54e44d38d2038ecf86b1a27e7ffc1411ee6ec7b3c4821ccb3d4e8e6b83f9c06000e110f37008f48b57e7841f4681a4d15f4d747443adf4871c8464bd5bd779019974c000000000000000000000000000000079865c87816d54b8c243712921892b693fe469293ef65388d1fc7a5c5b65727c790f0a70584e0e3bdefacb6bb05b00db4250b309d3457a99008317f652be5081608ba483f1");
    }

    fn ton_messages() -> Vec<Message> {
        vec![Message {
            cc_id: CrossChainId::new(
                "ganache-1",
                "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
            )
            .unwrap(),
            source_address: "0x52444f1835Adc02086c37Cb226561605e2E1699b"
                .parse()
                .unwrap(),
            destination_address:
                "0:4686a2c066c784a915f3e01c853d3195ed254c948e21adbb3e4a9b3f5f3c74d7"
                    .parse()
                    .unwrap(),
            destination_chain: "ton".parse().unwrap(),
            payload_hash: HexBinary::from_hex(
                "56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432", // keccak256("0x1234");
            )
            .unwrap()
            .to_array::<32>()
            .unwrap(),
        }]
    }

    fn signers_with_sigs<'a>(
        signers: impl Iterator<Item = &'a Signer>,
        sigs: Vec<HexBinary>,
    ) -> Vec<SignerWithSig> {
        signers
            .sorted_by(|s1, s2| Ord::cmp(&s1.pub_key, &s2.pub_key))
            .zip(sigs)
            .map(|(signer, sig)| {
                signer.with_sig(Signature::try_from((signer.pub_key.key_type(), sig)).unwrap())
            })
            .collect()
    }

    fn curr_ton_verifier_set() -> VerifierSet {
        let pub_keys = vec![
            "03A107BFF3CE10BE1D70DD18E74BC09967E4D6309BA50D5F1DDC8664125531B8",
            "43CDC023D22D5F9E107D1A0693457D35D1D10EB7D21C721192F56F5DE40665D3",
            "79B5562E8FE654F94078B112E8A98BA7901F853AE695BED7E0E3910BAD049664",
        ];

        ton_verifier_set_from_pub_keys(&pub_keys)
    }

    fn ton_verifier_set_from_pub_keys(pub_keys: &[&str]) -> VerifierSet {
        let participants: Vec<(_, _)> = (0..pub_keys.len())
            .map(|i| {
                (
                    Participant {
                        address: Addr::unchecked(format!("verifier{i}")),
                        weight: nonempty::Uint128::one(),
                    },
                    multisig::key::PublicKey::Ed25519(HexBinary::from_hex(pub_keys[i]).unwrap()),
                )
            })
            .collect();
        VerifierSet::new(participants, Uint128::from(3u128), 1)
    }

    fn incorrect_key_type_curr_ton_verifier_set() -> VerifierSet {
        let pub_keys = vec![
            "03A107BFF3CE10BE1D70DD18E74BC09967E4D6309BA50D5F1DDC8664125531B8",
            "43CDC023D22D5F9E107D1A0693457D35D1D10EB7D21C721192F56F5DE40665D3",
            "79B5562E8FE654F94078B112E8A98BA7901F853AE695BED7E0E3910BAD049664",
        ];

        ton_incorrect_key_type_verifier_set_from_pub_keys(&pub_keys)
    }

    fn ton_incorrect_key_type_verifier_set_from_pub_keys(pub_keys: &[&str]) -> VerifierSet {
        let participants: Vec<(_, _)> = (0..pub_keys.len())
            .map(|i| {
                (
                    Participant {
                        address: Addr::unchecked(format!("verifier{i}")),
                        weight: nonempty::Uint128::one(),
                    },
                    multisig::key::PublicKey::Ecdsa(HexBinary::from_hex(pub_keys[i]).unwrap()),
                )
            })
            .collect();
        VerifierSet::new(participants, Uint128::from(3u128), 1)
    }

    fn ton_domain_separator() -> [u8; 32] {
        HexBinary::from_hex("6973c72935604464b28827141b0a463af8e3487616de69c5aa0c785392c9fb9f")
            .unwrap()
            .to_array()
            .unwrap()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut output, b| {
            // write! returns a Result; we can ignore the error here
            let _ = write!(&mut output, "{:02x}", b);
            output
        })
    }
}
