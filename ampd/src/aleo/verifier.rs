use aleo_gmp_types::aleo_struct::generated_structs::SignersRotated;
use aleo_gmp_types::aleo_struct::AxelarToLeo as _;
use axelar_wasm_std::voting::Vote;
use snarkvm::prelude::Network;
use tracing::warn;

use super::CallContractReceipt;
use crate::aleo::receipt_builder::Receipt;
use crate::handlers::aleo_verify_msg::Message;
use crate::handlers::aleo_verify_verifier_set::VerifierSetConfirmation;

pub fn verify_message<N: Network>(
    receipt: &Receipt<N, CallContractReceipt<N>>,
    msg: &Message<N>,
) -> Vote {
    let res = match receipt {
        Receipt::Found(transition_receipt) => transition_receipt == msg,
        Receipt::NotFound(transition, e) => {
            warn!("AleoMessageId: {:#?} is not verified: {:?}", transition, e);

            false
        }
    };

    match res {
        true => Vote::SucceededOnChain,
        false => Vote::FailedOnChain,
    }
}

pub fn verify_verifier_set<N: Network>(
    receipt: &Receipt<N, SignersRotated<N>>,
    msg: &VerifierSetConfirmation<N>,
) -> Vote {
    let res = match receipt {
        Receipt::Found(signer_rotation) => msg
            .verifier_set
            .to_leo()
            .is_ok_and(|other| other == signer_rotation.new_signers_data),
        Receipt::NotFound(transition, e) => {
            warn!("AleoMessageId: {:?} is not verified: {:?}", transition, e);

            false
        }
    };

    match res {
        true => Vote::SucceededOnChain,
        false => Vote::FailedOnChain,
    }
}
