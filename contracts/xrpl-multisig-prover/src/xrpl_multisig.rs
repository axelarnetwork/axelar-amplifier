use std::collections::BTreeSet;

use axelar_wasm_std::nonempty;
use connection_router::state::CrossChainId;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{wasm_execute, HexBinary, Storage, Uint128, Uint64, WasmMsg};
use k256::{ecdsa, schnorr::signature::SignatureEncoding};
use multisig::key::PublicKey;
use ripemd::Ripemd160;
use sha2::{Sha512, Digest, Sha256};

use crate::{
    axelar_workers::{AxelarSigner, WorkerSet}, error::ContractError, state::{Config, AVAILABLE_TICKETS, CONFIRMED_TRANSACTIONS, CURRENT_WORKER_SET, LAST_ASSIGNED_TICKET_NUMBER, LATEST_SEQUENTIAL_TX_HASH, MESSAGE_ID_TO_TICKET, NEXT_SEQUENCE_NUMBER, NEXT_WORKER_SET, TRANSACTION_INFO}, types::*, xrpl_serialize::XRPLTokenAmount
};

#[cw_serde]
pub enum XRPLPaymentAmount {
    Drops(
        u64,
    ),
    Token(XRPLToken, XRPLTokenAmount),
}

#[cw_serde]
pub enum Sequence {
    Plain(u32),
    Ticket(u32),
}

impl Into<u32> for Sequence {
    fn into(self) -> u32 {
        match self {
            Sequence::Plain(sequence) => sequence,
            Sequence::Ticket(ticket) => ticket,
        }
    }
}

#[cw_serde]
pub struct XRPLSignerEntry {
    pub account: XRPLAccountId,
    pub signer_weight: u16,
}    

#[cw_serde]
pub enum XRPLUnsignedTx {
    Payment(XRPLPaymentTx),
    SignerListSet(XRPLSignerListSetTx),
    TicketCreate(XRPLTicketCreateTx),
}

impl XRPLUnsignedTx {
    pub fn sequence(&self) -> &Sequence {
        match self {
            XRPLUnsignedTx::Payment(tx) => {
                &tx.sequence
            },
            XRPLUnsignedTx::TicketCreate(tx) => {
                &tx.sequence
            },
            XRPLUnsignedTx::SignerListSet(tx) => {
                &tx.sequence
            }
        }
    }
    pub fn sequence_number_increment(&self, status: TransactionStatus) -> u32 {
        if status == TransactionStatus::Pending || status == TransactionStatus::Inconclusive {
            return 0;
        }

        match self {
            XRPLUnsignedTx::Payment(tx ) => {
                match tx.sequence {
                    Sequence::Plain(_) => 1,
                    Sequence::Ticket(_) => 0,
                }
            }
            XRPLUnsignedTx::SignerListSet(tx) => {
                match tx.sequence {
                    Sequence::Plain(_) => 1,
                    Sequence::Ticket(_) => 0,
                }
            },
            XRPLUnsignedTx::TicketCreate(tx) => {
                match status {
                    TransactionStatus::Succeeded => tx.ticket_count + 1,
                    TransactionStatus::FailedOnChain => 1,
                    TransactionStatus::Inconclusive |
                    TransactionStatus::Pending => unreachable!(),
                }
            },
        }
    }
}

#[cw_serde]
pub struct XRPLPaymentTx {
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: Sequence,
    pub amount: XRPLPaymentAmount,
    pub destination: XRPLAccountId,
    pub multisig_session_id: Uint64
}

#[cw_serde]
pub struct XRPLSignerListSetTx {
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: Sequence,
    pub signer_quorum: u32,
    pub signer_entries: Vec<XRPLSignerEntry>,
    pub multisig_session_id: Uint64
}

#[cw_serde]
pub struct XRPLTicketCreateTx {
    pub account: XRPLAccountId,
    pub fee: u64,
    pub sequence: Sequence,
    pub ticket_count: u32,
    pub multisig_session_id: Uint64
}

#[cw_serde]
pub struct XRPLAccountId([u8; 20]);

impl XRPLAccountId {
    pub const fn to_bytes(&self) -> [u8; 20] {
        return self.0;
    }

    pub fn to_string(&self) -> String {
        let address_type_prefix: &[u8] = &[0x00];
        let payload = [address_type_prefix, &self.to_bytes()].concat();

        let checksum_hash1 = Sha256::digest(payload.clone());
        let checksum_hash2 = Sha256::digest(checksum_hash1);
        let checksum = &checksum_hash2[0..4];

        bs58::encode([payload, checksum.to_vec()].concat())
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .into_string()
    }
}

impl From<&PublicKey> for XRPLAccountId {
    fn from(pub_key: &PublicKey) -> Self {
        let public_key_hex: HexBinary = pub_key.clone().into();

        assert!(public_key_hex.len() == 33);

        let public_key_inner_hash = Sha256::digest(public_key_hex);
        let account_id = Ripemd160::digest(public_key_inner_hash);

        return XRPLAccountId(account_id.into());
    }
}

impl TryFrom<&str> for XRPLAccountId {
    type Error = ContractError;

    fn try_from(address: &str) -> Result<Self, ContractError> {
        let res = bs58::decode(address).with_alphabet(bs58::Alphabet::RIPPLE).into_vec().map_err(|_| ContractError::InvalidAddress)?;
        // .map_err(|_| ContractError::InvalidAddress)?;
        if res.len() != 25 {
            return Err(ContractError::InvalidAddress);
        }
        let mut buffer = [0u8; 20];
        buffer.copy_from_slice(&res[1..21]);
        return Ok(XRPLAccountId(buffer))
    }
}

#[cw_serde]
pub struct XRPLSigner {
    pub account: XRPLAccountId,
    pub txn_signature: HexBinary,
    pub signing_pub_key: PublicKey,
}

#[cw_serde]
pub struct XRPLSignedTransaction {
    pub unsigned_tx: XRPLUnsignedTx,
    pub signers: Vec<XRPLSigner>
}

pub fn get_next_ticket_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    let last_assigned_ticket_number: u32 = LAST_ASSIGNED_TICKET_NUMBER.load(storage)?;
    // TODO: handle no available tickets
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;

    // find next largest in available, otherwise use available_tickets[0]
    // TODO: handle IndexOutOfBounds error on available_tickets[0]
    let ticket_number = available_tickets.iter().find(|&x| x > &last_assigned_ticket_number).unwrap_or(&available_tickets[0]);
    Ok(*ticket_number)
}

pub fn available_ticket_count(storage: &mut dyn Storage) -> Result<u32, ContractError> {
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;
    let ticket_count = 250 - (available_tickets.len() as u32);
    Ok(ticket_count)
}


pub const HASH_PREFIX_SIGNED_TRANSACTION: [u8; 4] = [0x54, 0x58, 0x4E, 0x00];
pub const HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING: [u8; 4] = [0x53, 0x4D, 0x54, 0x00];

pub fn compute_unsigned_tx_hash(unsigned_tx: &XRPLUnsignedTx) -> Result<TxHash, ContractError> {
    let encoded_unsigned_tx = serde_json::to_vec(unsigned_tx).map_err(|_| ContractError::FailedToSerialize)?;

    let d = Sha256::digest(encoded_unsigned_tx);
    Ok(TxHash(HexBinary::from(d.to_vec())))
}

pub fn compute_signed_tx_hash(encoded_signed_tx: Vec<u8>) -> Result<TxHash, ContractError> {
    Ok(TxHash(HexBinary::from(xrpl_hash(HASH_PREFIX_SIGNED_TRANSACTION, encoded_signed_tx.as_slice()))))
}

pub fn message_to_sign(encoded_unsigned_tx: &HexBinary, signer_address: &XRPLAccountId) -> Result<[u8; 32], ContractError> {
    let msg = &[encoded_unsigned_tx.to_vec(), signer_address.to_bytes().into()].concat();
    Ok(xrpl_hash(HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING, msg))
}

pub fn xrpl_hash(
    prefix: [u8; 4],
    tx_blob: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha512::new_with_prefix(prefix);
    hasher.update(tx_blob);
    let hash: [u8; 64] = hasher.finalize().into();
    let mut half_hash: [u8; 32] = [0; 32];
    half_hash.copy_from_slice(&hash[..32]);
    half_hash
}

fn issue_tx(
    storage: &mut dyn Storage,
    tx: XRPLUnsignedTx,
    message_id: Option<CrossChainId>,
) -> Result<TxHash, ContractError> {
    let tx_hash = compute_unsigned_tx_hash(&tx)?;

    TRANSACTION_INFO.save(
        storage,
        &tx_hash,
        &TransactionInfo {
            status: TransactionStatus::Pending,
            unsigned_contents: tx.clone(),
            message_id,
        }
    )?;

    match tx.sequence() {
        Sequence::Ticket(ticket_number) => {
            LAST_ASSIGNED_TICKET_NUMBER.save(storage, &ticket_number)?;
        },
        Sequence::Plain(_) => {
            LATEST_SEQUENTIAL_TX_HASH.save(storage, &tx_hash)?;
        },
    };

    Ok(tx_hash)
}

pub fn issue_payment(
    storage: &mut dyn Storage,
    config: &Config,
    destination: nonempty::String,
    amount: &XRPLPaymentAmount,
    message_id: &CrossChainId,
    multisig_session_id: &Uint64,
) -> Result<TxHash, ContractError> {
    let ticket_number = assign_ticket_number(storage, message_id)?;

    let tx = XRPLPaymentTx {
        account: config.xrpl_multisig_address.as_str().try_into()?,
        fee: config.xrpl_fee,
        sequence: Sequence::Ticket(ticket_number),
        multisig_session_id: multisig_session_id.clone(),
        amount: amount.clone(),
        destination: XRPLAccountId::try_from(destination.as_str())?
    };

    issue_tx(
        storage,
        XRPLUnsignedTx::Payment(tx),
        Some(message_id.clone()),
    )
}

pub fn issue_ticket_create(
    storage: &mut dyn Storage,
    config: &Config,
    ticket_count: u32,
    multisig_session_id: Uint64
) -> Result<TxHash, ContractError> {
    let sequence_number = get_next_sequence_number(storage)?;

    let tx = XRPLTicketCreateTx {
        account: config.xrpl_multisig_address.as_str().try_into()?,
        fee: config.xrpl_fee,
        sequence: Sequence::Plain(sequence_number.clone()),
        ticket_count,
        multisig_session_id,
    };

    issue_tx(
        storage,
        XRPLUnsignedTx::TicketCreate(tx),
        None,
    )
}

pub fn issue_signer_list_set(
    storage: &mut dyn Storage,
    config: &Config,
    workers: WorkerSet,
    multisig_session_id: Uint64
) -> Result<TxHash, ContractError> {
    let sequence_number = get_next_sequence_number(storage)?;

    let tx = XRPLSignerListSetTx {
        account: config.xrpl_multisig_address.as_str().try_into()?,
        fee: config.xrpl_fee,
        sequence: Sequence::Plain(sequence_number.clone()),
        signer_quorum: workers.quorum,
        signer_entries: make_xrpl_signer_entries(workers.signers)?,
        multisig_session_id,
    };

    issue_tx(
        storage,
        XRPLUnsignedTx::SignerListSet(tx),
        None,
    )
}

fn make_xrpl_signer_entries(signers: BTreeSet<AxelarSigner>) -> Result<Vec<XRPLSignerEntry>, ContractError> {
    signers
        .into_iter()
        .map(
            |worker| -> Result<XRPLSignerEntry, ContractError> {
                Ok(XRPLSignerEntry {
                    account: XRPLAccountId::from(&worker.pub_key),
                    signer_weight: worker.weight,
                })
            }
        ).collect()
}


fn get_next_sequence_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    match load_latest_sequential_tx_info(storage)? {
        Some(latest_sequential_tx_info) if latest_sequential_tx_info.status == TransactionStatus::Pending => {
            Ok(latest_sequential_tx_info.unsigned_contents.sequence().clone().into())
        },
        _ => NEXT_SEQUENCE_NUMBER.load(storage).map_err(|e| e.into())
    }
}

fn load_latest_sequential_tx_info(
    storage: &dyn Storage,
) -> Result<Option<TransactionInfo>, ContractError> {
    LATEST_SEQUENTIAL_TX_HASH
    .may_load(storage)?
    .map_or(Ok(None), |tx_hash| Ok(TRANSACTION_INFO.may_load(storage, &tx_hash)?))
}

fn mark_tickets_available(storage: &mut dyn Storage, tickets: impl Iterator<Item = u32>) -> Result<(), ContractError> {
    AVAILABLE_TICKETS.update(storage, |available_tickets| -> Result<_, ContractError> {
        let mut new_available_tickets = available_tickets.clone();
        new_available_tickets.extend(tickets);
        Ok(new_available_tickets)
    })?;
    Ok(())
}

fn mark_ticket_unavailable(storage: &mut dyn Storage, ticket: u32) -> Result<(), ContractError> {
    AVAILABLE_TICKETS.update(storage, |available_tickets| -> Result<_, ContractError> {
        Ok(available_tickets
            .into_iter()
            .filter(|&x| x != ticket)
            .collect())
    })?;
    Ok(())
}

pub fn make_xrpl_signed_tx(unsigned_tx: XRPLUnsignedTx, axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)>) -> Result<XRPLSignedTransaction, ContractError> {
    let xrpl_signers: Vec<XRPLSigner> = axelar_signers
        .iter()
        .map(|(axelar_signer, signature)| -> Result<XRPLSigner, ContractError> {
            let txn_signature = match signature {
                // TODO: use unwrapped signature instead of ignoring it
                multisig::key::Signature::Ecdsa(_) |
                multisig::key::Signature::EcdsaRecoverable(_) => HexBinary::from(ecdsa::Signature::to_der(
                    &ecdsa::Signature::try_from(signature.clone().as_ref())
                        .map_err(|_| ContractError::FailedToEncodeSignature)?
                ).to_vec()),
                _ => unimplemented!("Unsupported signature type"),
            };

            Ok(XRPLSigner {
                account: XRPLAccountId::from(&axelar_signer.pub_key),
                signing_pub_key: axelar_signer.pub_key.clone().into(),
                txn_signature,
            })
        })
        .collect::<Result<Vec<XRPLSigner>, ContractError>>()?;

    Ok(XRPLSignedTransaction {
        unsigned_tx,
        signers: xrpl_signers,
    })
}

pub fn update_tx_status(
    storage: &mut dyn Storage,
    axelar_multisig_address: impl Into<String>,
    unsigned_tx_hash: TxHash,
    new_status: TransactionStatus
) -> Result<Option<WasmMsg>, ContractError> {
    let mut tx_info = TRANSACTION_INFO.load(storage, &unsigned_tx_hash)?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TransactionStatusAlreadyUpdated);
    }

    tx_info.status = new_status.clone();

    let tx_sequence_number: u32 = tx_info.unsigned_contents.sequence().clone().into();

    let sequence_number_increment = tx_info.unsigned_contents.sequence_number_increment(new_status.clone());
    if sequence_number_increment > 0 && tx_sequence_number == NEXT_SEQUENCE_NUMBER.load(storage)? {
        NEXT_SEQUENCE_NUMBER.save(storage, &(tx_sequence_number + sequence_number_increment))?;
    }

    if new_status == TransactionStatus::Succeeded || new_status == TransactionStatus::FailedOnChain {
        CONFIRMED_TRANSACTIONS.save(storage, &tx_sequence_number, &unsigned_tx_hash)?;
        mark_ticket_unavailable(storage, tx_sequence_number)?;
    }

    TRANSACTION_INFO.save(storage, &unsigned_tx_hash, &tx_info)?;

    if tx_info.status != TransactionStatus::Succeeded {
        return Ok(None);
    }

    let res = match &tx_info.unsigned_contents {
        XRPLUnsignedTx::TicketCreate(tx) => {
            mark_tickets_available(
                storage,
                (tx_sequence_number + 1)..(tx_sequence_number + tx.ticket_count),
            )?;
            None
        },
        XRPLUnsignedTx::SignerListSet(_tx) => {
            let next_worker_set = NEXT_WORKER_SET.load(storage, &unsigned_tx_hash)?;
            CURRENT_WORKER_SET.save(storage, &next_worker_set)?;
            NEXT_WORKER_SET.remove(storage, &unsigned_tx_hash);

            let msg = wasm_execute(
                axelar_multisig_address,
                &multisig::msg::ExecuteMsg::RegisterWorkerSet {
                    worker_set: next_worker_set.into(),
                },
                vec![],
            )?;
            Some(msg)
        },
        XRPLUnsignedTx::Payment(_) => None
    };

    Ok(res)
}

// A message ID can be ticketed a different ticket number
// only if the previous ticket number has been consumed
// by a TX that doesn't correspond to this message.
pub fn assign_ticket_number(storage: &mut dyn Storage, message_id: &CrossChainId) -> Result<u32, ContractError> {
    // If this message ID has already been ticketed,
    // then use the same ticket number as before,
    if let Some(ticket_number) = MESSAGE_ID_TO_TICKET.may_load(storage, &message_id)? {
        let confirmed_tx_hash = CONFIRMED_TRANSACTIONS.may_load(storage, &ticket_number)?;
        // as long as it has not already been consumed
        if confirmed_tx_hash.is_none() 
        // or if it has been consumed by the same message.
        || TRANSACTION_INFO.load(storage, &confirmed_tx_hash.unwrap())?.message_id.as_ref() == Some(message_id) {
            return Ok(ticket_number);
        }
    }

    // Otherwise, use the next available ticket number.
    let new_ticket_number = get_next_ticket_number(storage)?;
    MESSAGE_ID_TO_TICKET.save(storage, message_id, &new_ticket_number)?;
    Ok(new_ticket_number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_id_to_bytes_address() {
        assert_eq!("rrrrrrrrrrrrrrrrrrrrrhoLvTp", XRPLAccountId([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string());
        assert_eq!("rQLbzfJH5BT1FS9apRLKV3G8dWEA5njaQi", XRPLAccountId([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]).to_string());
    }
    #[test]
    fn ed25519_public_key_to_xrpl_address() -> Result<(), ContractError> {
        assert_eq!(
            XRPLAccountId::from(&PublicKey::Ed25519(HexBinary::from_hex("ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32")?)).to_string(),
            "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN"
        );
        Ok(())
    }

    #[test]
    fn secp256k1_public_key_to_xrpl_address() -> Result<(), ContractError> {
        assert_eq!(
            XRPLAccountId::from(&PublicKey::Ecdsa(HexBinary::from_hex("0303E20EC6B4A39A629815AE02C0A1393B9225E3B890CAE45B59F42FA29BE9668D")?)).to_string(),
            "rnBFvgZphmN39GWzUJeUitaP22Fr9be75H"
        );
        Ok(())
    }
}