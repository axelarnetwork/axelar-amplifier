use router_api::CrossChainId;
use cosmwasm_std::Storage;
use xrpl_types::types::{
    TxHash, XRPLUnsignedTx, TxInfo, TransactionStatus, XRPLSequence,
    XRPLAccountId, XRPLPaymentAmount, XRPLCrossCurrencyOptions, XRPLToken, XRPLPaymentTx,
    XRPLTicketCreateTx, XRPLSignerListSetTx, XRPLSignerEntry, XRPLTrustSetTx,
};

use crate::axelar_verifiers::VerifierSet;
use crate::error::ContractError;
use crate::state::{
    Config, AVAILABLE_TICKETS, CONFIRMED_TRANSACTIONS, CURRENT_VERIFIER_SET,
    LAST_ASSIGNED_TICKET_NUMBER, LATEST_SEQUENTIAL_UNSIGNED_TX_HASH, CROSS_CHAIN_ID_TO_TICKET,
    NEXT_SEQUENCE_NUMBER, NEXT_VERIFIER_SET, UNSIGNED_TX_HASH_TO_TX_INFO,
};

fn issue_tx(
    storage: &mut dyn Storage,
    unsigned_tx: XRPLUnsignedTx,
    original_cc_id: Option<CrossChainId>,
) -> Result<TxHash, ContractError> {
    let unsigned_tx_hash = xrpl_types::types::hash_unsigned_tx(&unsigned_tx)?;

    UNSIGNED_TX_HASH_TO_TX_INFO.save(
        storage,
        &unsigned_tx_hash,
        &TxInfo {
            status: TransactionStatus::Pending,
            unsigned_contents: unsigned_tx.clone(),
            original_cc_id,
        },
    )?;

    match unsigned_tx.sequence() {
        XRPLSequence::Ticket(ticket_number) => {
            LAST_ASSIGNED_TICKET_NUMBER.save(storage, ticket_number)?;
        }
        XRPLSequence::Plain(_) => {
            LATEST_SEQUENTIAL_UNSIGNED_TX_HASH.save(storage, &unsigned_tx_hash)?;
        }
    };

    Ok(unsigned_tx_hash)
}

pub fn issue_payment(
    storage: &mut dyn Storage,
    config: &Config,
    destination: XRPLAccountId,
    amount: &XRPLPaymentAmount,
    cc_id: &CrossChainId,
    cross_currency: Option<&XRPLCrossCurrencyOptions>,
) -> Result<TxHash, ContractError> {
    let ticket_number = assign_ticket_number(storage, cc_id)?;

    let tx = XRPLPaymentTx {
        account: config.xrpl_multisig.clone(),
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Ticket(ticket_number),
        amount: amount.clone(),
        destination,
        cross_currency: cross_currency.cloned()
    };

    issue_tx(storage, XRPLUnsignedTx::Payment(tx), Some(cc_id.clone()))
}

pub fn issue_ticket_create(
    storage: &mut dyn Storage,
    config: &Config,
    ticket_count: u32,
) -> Result<TxHash, ContractError> {
    let sequence_number = next_sequence_number(storage)?;

    let tx = XRPLTicketCreateTx {
        account: config.xrpl_multisig.clone(),
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Plain(sequence_number),
        ticket_count,
    };

    issue_tx(storage, XRPLUnsignedTx::TicketCreate(tx), None)
}

pub fn issue_trust_set(
    storage: &mut dyn Storage,
    config: &Config,
    xrpl_token: XRPLToken,
) -> Result<TxHash, ContractError> {
    let sequence_number = next_sequence_number(storage)?;

    let tx = XRPLTrustSetTx {
        token: xrpl_token,
        account: config.xrpl_multisig.clone(),
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Plain(sequence_number),
    };

    issue_tx(storage, XRPLUnsignedTx::TrustSet(tx), None)
}

pub fn issue_signer_list_set(
    storage: &mut dyn Storage,
    config: &Config,
    verifier_set: VerifierSet,
) -> Result<TxHash, ContractError> {
    let sequence_number = next_sequence_number(storage)?;

    let tx = XRPLSignerListSetTx {
        account: config.xrpl_multisig.clone(),
        fee: config.xrpl_fee,
        sequence: XRPLSequence::Plain(sequence_number),
        signer_quorum: verifier_set.quorum,
        signer_entries: verifier_set
            .signers
            .into_iter()
            .map(XRPLSignerEntry::from)
            .collect(),
    };

    issue_tx(storage, XRPLUnsignedTx::SignerListSet(tx), None)
}

// returns the new verifier set if it was affected
pub fn update_tx_status(
    storage: &mut dyn Storage,
    unsigned_tx_hash: TxHash,
    new_status: TransactionStatus,
) -> Result<Option<VerifierSet>, ContractError> {
    let mut tx_info = UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &unsigned_tx_hash)?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TxStatusAlreadyUpdated);
    }

    tx_info.status = new_status.clone();

    let tx_sequence_number: u32 = tx_info.unsigned_contents.sequence().clone().into();

    let sequence_number_increment = tx_info
        .unsigned_contents
        .sequence_number_increment(new_status.clone());
    if sequence_number_increment > 0 && tx_sequence_number == NEXT_SEQUENCE_NUMBER.load(storage)? {
        NEXT_SEQUENCE_NUMBER.save(storage, &(tx_sequence_number + sequence_number_increment))?;
    }

    if new_status == TransactionStatus::Succeeded || new_status == TransactionStatus::FailedOnChain {
        CONFIRMED_TRANSACTIONS.save(storage, &tx_sequence_number, &unsigned_tx_hash)?;
        mark_ticket_unavailable(storage, tx_sequence_number)?;
    }

    UNSIGNED_TX_HASH_TO_TX_INFO.save(storage, &unsigned_tx_hash, &tx_info)?;

    if tx_info.status != TransactionStatus::Succeeded {
        return Ok(None);
    }

    Ok(match &tx_info.unsigned_contents {
        XRPLUnsignedTx::TicketCreate(tx) => {
            mark_tickets_available(
                storage,
                (tx_sequence_number + 1)..(tx_sequence_number + tx.ticket_count + 1)
            )?;
            None
        }
        XRPLUnsignedTx::SignerListSet(tx) => {
            let next_verifier_set = NEXT_VERIFIER_SET
                .may_load(storage)?
                .ok_or(ContractError::NoVerifierSetToConfirm)?;

            let signer_entries: Vec<XRPLSignerEntry> = next_verifier_set.clone()
                .signers
                .into_iter()
                .map(XRPLSignerEntry::from)
                .collect();

            // sanity check
            if signer_entries != tx.signer_entries || tx.signer_quorum != next_verifier_set.quorum {
                return Err(ContractError::SignerListMismatch);
            }

            CURRENT_VERIFIER_SET.save(storage, &next_verifier_set)?;
            NEXT_VERIFIER_SET.remove(storage);

            Some(next_verifier_set)
        }
        XRPLUnsignedTx::Payment(_) | XRPLUnsignedTx::TrustSet(_) => None, // nothing to do
    })
}

// TICKET / SEQUENCE NUMBER ASSIGNEMENT LOGIC

// A message ID can be ticketed a different ticket number
// only if the previous ticket number has been consumed
// by a TX that doesn't correspond to this message.
fn assign_ticket_number(
    storage: &mut dyn Storage,
    cc_id: &CrossChainId,
) -> Result<u32, ContractError> {
    // If this message ID has already been ticketed,
    // then use the same ticket number as before,
    if let Some(ticket_number) = CROSS_CHAIN_ID_TO_TICKET.may_load(storage, cc_id)? {
        let confirmed_unsigned_tx_hash = CONFIRMED_TRANSACTIONS.may_load(storage, &ticket_number)?;
        // as long as it has not already been consumed
        if confirmed_unsigned_tx_hash.is_none()
        // or if it has been consumed by the same message.
        || UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &confirmed_unsigned_tx_hash.unwrap())?.original_cc_id.as_ref() == Some(cc_id)
        {
            return Ok(ticket_number);
        }
    }

    // Otherwise, use the next available ticket number.
    let new_ticket_number = next_ticket_number(storage)?;
    CROSS_CHAIN_ID_TO_TICKET.save(storage, cc_id, &new_ticket_number)?;
    Ok(new_ticket_number)
}

fn next_ticket_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    let last_assigned_ticket_number: u32 = LAST_ASSIGNED_TICKET_NUMBER.load(storage)?;

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

const MAX_TICKET_COUNT: u32 = 250;

pub fn tickets_available_to_request(storage: &mut dyn Storage) -> Result<u32, ContractError> {
    let available_tickets = AVAILABLE_TICKETS.load(storage)?;
    let available_ticket_count = u32::try_from(available_tickets.len()).expect("ticket count overflow");
    assert!(available_ticket_count <= MAX_TICKET_COUNT);
    Ok(MAX_TICKET_COUNT - available_ticket_count)
}

fn next_sequence_number(storage: &dyn Storage) -> Result<u32, ContractError> {
    match load_latest_sequential_tx_info(storage)? {
        Some(latest_sequential_tx_info)
            if latest_sequential_tx_info.status == TransactionStatus::Pending =>
            // this might still be pending but another tx with same sequence number may be confirmed!!!
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
) -> Result<Option<TxInfo>, ContractError> {
    LATEST_SEQUENTIAL_UNSIGNED_TX_HASH
        .may_load(storage)?
        .map_or(Ok(None), |tx_hash| {
            Ok(UNSIGNED_TX_HASH_TO_TX_INFO.may_load(storage, &tx_hash)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::HexBinary;
    use multisig::key::PublicKey;

    #[test]
    fn test_account_id_to_bytes() {
        assert_eq!(
            "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
            XRPLAccountId::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                .to_string()
        );
        assert_eq!(
            "rQLbzfJH5BT1FS9apRLKV3G8dWEA5njaQi",
            XRPLAccountId::from([
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
