use axelar_wasm_std::nonempty;
use connection_router_api::CrossChainId;
use cosmwasm_std::{wasm_execute, HexBinary, Response, Storage};
use sha2::{Digest, Sha256, Sha512};
use std::str::FromStr;

use crate::{
    axelar_workers::WorkerSet,
    error::ContractError,
    state::{
        Config, AVAILABLE_TICKETS, CONFIRMED_TRANSACTIONS, CURRENT_WORKER_SET,
        LAST_ASSIGNED_TICKET_NUMBER, LATEST_SEQUENTIAL_TX_HASH, MESSAGE_ID_TO_TICKET,
        NEXT_SEQUENCE_NUMBER, NEXT_WORKER_SET, TRANSACTION_INFO,
    },
    types::*,
};

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
            original_message_id: message_id,
        },
    )?;

    match tx.sequence() {
        XRPLSequence::Ticket(ticket_number) => {
            LAST_ASSIGNED_TICKET_NUMBER.save(storage, ticket_number)?;
        }
        XRPLSequence::Plain(_) => {
            LATEST_SEQUENTIAL_TX_HASH.save(storage, &tx_hash)?;
        }
    };

    Ok(tx_hash)
}

pub fn issue_payment(
    storage: &mut dyn Storage,
    config: &Config,
    destination: nonempty::String,
    amount: &XRPLPaymentAmount,
    message_id: &CrossChainId,
) -> Result<TxHash, ContractError> {
    let ticket_number = assign_ticket_number(storage, message_id)?;

    let tx = XRPLPaymentTx {
        account: XRPLAccountId::from_str(config.xrpl_multisig.as_str())?,
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Ticket(ticket_number),
        amount: amount.clone(),
        destination: XRPLAccountId::from_str(destination.as_str())?,
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
) -> Result<TxHash, ContractError> {
    let sequence_number = get_next_sequence_number(storage)?;

    let tx = XRPLTicketCreateTx {
        account: XRPLAccountId::from_str(config.xrpl_multisig.as_str())?,
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Plain(sequence_number),
        ticket_count,
    };

    issue_tx(storage, XRPLUnsignedTx::TicketCreate(tx), None)
}

pub fn issue_signer_list_set(
    storage: &mut dyn Storage,
    config: &Config,
    workers: WorkerSet,
) -> Result<TxHash, ContractError> {
    let sequence_number = get_next_sequence_number(storage)?;

    let tx = XRPLSignerListSetTx {
        account: XRPLAccountId::from_str(config.xrpl_multisig.as_str())?,
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Plain(sequence_number),
        signer_quorum: workers.quorum,
        signer_entries: workers
            .signers
            .into_iter()
            .map(XRPLSignerEntry::from)
            .collect(),
    };

    issue_tx(storage, XRPLUnsignedTx::SignerListSet(tx), None)
}

pub fn update_tx_status(
    storage: &mut dyn Storage,
    config: &Config,
    unsigned_tx_hash: TxHash,
    new_status: TransactionStatus,
) -> Result<Response, ContractError> {
    let mut tx_info = TRANSACTION_INFO.load(storage, &unsigned_tx_hash)?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TransactionStatusAlreadyUpdated);
    }

    tx_info.status = new_status.clone();

    let tx_sequence_number: u32 = tx_info.unsigned_contents.sequence().clone().into();

    let sequence_number_increment = tx_info
        .unsigned_contents
        .sequence_number_increment(new_status.clone());
    if sequence_number_increment > 0 && tx_sequence_number == NEXT_SEQUENCE_NUMBER.load(storage)? {
        NEXT_SEQUENCE_NUMBER.save(storage, &(tx_sequence_number + sequence_number_increment))?;
    }

    if new_status == TransactionStatus::Succeeded || new_status == TransactionStatus::FailedOnChain
    {
        CONFIRMED_TRANSACTIONS.save(storage, &tx_sequence_number, &unsigned_tx_hash)?;
        mark_ticket_unavailable(storage, tx_sequence_number)?;
    }

    TRANSACTION_INFO.save(storage, &unsigned_tx_hash, &tx_info)?;

    if tx_info.status != TransactionStatus::Succeeded {
        return Ok(Response::default());
    }

    Ok(match &tx_info.unsigned_contents {
        XRPLUnsignedTx::TicketCreate(tx) => {
            mark_tickets_available(
                storage,
                (tx_sequence_number + 1)..(tx_sequence_number + tx.ticket_count + 1)
            )?;
            Response::default()
        }
        XRPLUnsignedTx::SignerListSet(_tx) => {
            let next_worker_set = NEXT_WORKER_SET.load(storage, &unsigned_tx_hash)?;
            CURRENT_WORKER_SET.save(storage, &next_worker_set)?;
            NEXT_WORKER_SET.remove(storage, &unsigned_tx_hash);

            Response::new()
                .add_message(wasm_execute(
                    config.axelar_multisig.clone(),
                    &multisig::msg::ExecuteMsg::RegisterWorkerSet {
                        worker_set: next_worker_set.clone().into(),
                    },
                    vec![],
                )?)
                .add_message(wasm_execute(
                    config.monitoring.clone(),
                    &monitoring::msg::ExecuteMsg::SetActiveVerifiers {
                        next_worker_set: next_worker_set.into(),
                    },
                    vec![],
                )?)
        }
        XRPLUnsignedTx::Payment(_) => Response::default(),
    })
}

// TICKET / SEQUENCE NUMBER ASSIGNEMENT LOGIC

// A message ID can be ticketed a different ticket number
// only if the previous ticket number has been consumed
// by a TX that doesn't correspond to this message.
pub fn assign_ticket_number(
    storage: &mut dyn Storage,
    message_id: &CrossChainId,
) -> Result<u32, ContractError> {
    // If this message ID has already been ticketed,
    // then use the same ticket number as before,
    if let Some(ticket_number) = MESSAGE_ID_TO_TICKET.may_load(storage, message_id)? {
        let confirmed_tx_hash = CONFIRMED_TRANSACTIONS.may_load(storage, &ticket_number)?;
        // as long as it has not already been consumed
        if confirmed_tx_hash.is_none()
        // or if it has been consumed by the same message.
        || TRANSACTION_INFO.load(storage, &confirmed_tx_hash.unwrap())?.original_message_id.as_ref() == Some(message_id)
        {
            return Ok(ticket_number);
        }
    }

    // Otherwise, use the next available ticket number.
    let new_ticket_number = get_next_ticket_number(storage)?;
    MESSAGE_ID_TO_TICKET.save(storage, message_id, &new_ticket_number)?;
    Ok(new_ticket_number)
}

pub fn get_next_ticket_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    let last_assigned_ticket_number: u32 = LAST_ASSIGNED_TICKET_NUMBER.load(storage)?;

    // TODO: handle no available tickets
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;

    if available_tickets.is_empty() {
        return Err(ContractError::NoAvailableTickets);
    }

    // find next largest in available, otherwise use available_tickets[0]
    let ticket_number = available_tickets
        .iter()
        .find(|&x| x > &last_assigned_ticket_number)
        .unwrap_or(&available_tickets[0]);
    Ok(*ticket_number)
}

pub fn tickets_available_to_request(storage: &mut dyn Storage) -> Result<u32, ContractError> {
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;
    let available_ticket_count = u32::try_from(available_tickets.len())
        .map_err(|e| ContractError::GenericError(e.to_string()))?;
    assert!(available_ticket_count <= 250);
    Ok(250 - available_ticket_count)
}

fn get_next_sequence_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    match load_latest_sequential_tx_info(storage)? {
        Some(latest_sequential_tx_info)
            if latest_sequential_tx_info.status == TransactionStatus::Pending =>
        {
            Ok(latest_sequential_tx_info
                .unsigned_contents
                .sequence()
                .clone()
                .into())
        }
        _ => NEXT_SEQUENCE_NUMBER.load(storage).map_err(|e| e.into()),
    }
}

fn load_latest_sequential_tx_info(
    storage: &dyn Storage,
) -> Result<Option<TransactionInfo>, ContractError> {
    LATEST_SEQUENTIAL_TX_HASH
        .may_load(storage)?
        .map_or(Ok(None), |tx_hash| {
            Ok(TRANSACTION_INFO.may_load(storage, &tx_hash)?)
        })
}

fn mark_tickets_available(
    storage: &mut dyn Storage,
    tickets: impl Iterator<Item = u32>,
) -> Result<(), ContractError> {
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

// HASHING LOGIC

pub const HASH_PREFIX_SIGNED_TRANSACTION: [u8; 4] = [0x54, 0x58, 0x4E, 0x00];
pub const HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING: [u8; 4] = [0x53, 0x4D, 0x54, 0x00];

pub fn xrpl_hash(prefix: [u8; 4], tx_blob: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new_with_prefix(prefix);
    hasher.update(tx_blob);
    let hash: [u8; 64] = hasher.finalize().into();
    hash[..32].try_into().unwrap()
}

pub fn compute_unsigned_tx_hash(unsigned_tx: &XRPLUnsignedTx) -> Result<TxHash, ContractError> {
    let encoded_unsigned_tx =
        serde_json::to_vec(unsigned_tx).map_err(|_| ContractError::FailedToSerialize)?;

    let d = Sha256::digest(encoded_unsigned_tx);
    Ok(TxHash(HexBinary::from(d.to_vec())))
}

pub fn compute_signed_tx_hash(encoded_signed_tx: &[u8]) -> Result<TxHash, ContractError> {
    Ok(TxHash(HexBinary::from(xrpl_hash(
        HASH_PREFIX_SIGNED_TRANSACTION,
        encoded_signed_tx,
    ))))
}

pub fn message_to_sign(
    encoded_unsigned_tx: &HexBinary,
    signer_address: &XRPLAccountId,
) -> Result<[u8; 32], ContractError> {
    let mut msg = encoded_unsigned_tx.to_vec();
    msg.extend_from_slice(&signer_address.to_bytes());
    Ok(xrpl_hash(
        HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING,
        msg.as_slice(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use multisig::key::PublicKey;

    #[test]
    fn test_account_id_to_bytes_address() {
        assert_eq!(
            "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
            XRPLAccountId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                .to_string()
        );
        assert_eq!(
            "rQLbzfJH5BT1FS9apRLKV3G8dWEA5njaQi",
            XRPLAccountId::from_bytes([
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255
            ])
            .to_string()
        );
    }
    #[test]
    fn ed25519_public_key_to_xrpl_address() -> Result<(), ContractError> {
        assert_eq!(
            XRPLAccountId::from(&PublicKey::Ed25519(HexBinary::from_hex(
                "ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32"
            )?))
            .to_string(),
            "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN"
        );
        Ok(())
    }

    #[test]
    fn secp256k1_public_key_to_xrpl_address() -> Result<(), ContractError> {
        assert_eq!(
            XRPLAccountId::from(&PublicKey::Ecdsa(HexBinary::from_hex(
                "0303E20EC6B4A39A629815AE02C0A1393B9225E3B890CAE45B59F42FA29BE9668D"
            )?))
            .to_string(),
            "rnBFvgZphmN39GWzUJeUitaP22Fr9be75H"
        );
        Ok(())
    }
}
