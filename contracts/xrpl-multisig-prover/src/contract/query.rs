use axelar_wasm_std::msg_id::HexTxHash;
use cosmwasm_std::{Addr, HexBinary, QuerierWrapper, StdResult, Storage, Uint64};
use multisig::key::{PublicKey, Signature};
use multisig::types::MultisigState;
use router_api::CrossChainId;
use xrpl_types::error::XRPLError;
use xrpl_types::types::{XRPLAccountId, XRPLSignedTx, XRPLSigner, XRPLUnsignedTxToSign};

use crate::error::ContractError;
use crate::msg::{ProofResponse, ProofStatus};
use crate::state::{
    MultisigSession, CROSS_CHAIN_ID_TO_MULTISIG_SESSION, CURRENT_VERIFIER_SET,
    MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH, NEXT_VERIFIER_SET, UNSIGNED_TX_HASH_TO_TX_INFO,
};
use crate::xrpl_multisig;
use crate::xrpl_serialize::XRPLSerialize;

fn message_to_sign(
    storage: &dyn Storage,
    multisig_session_id: &Uint64,
    signer_xrpl_address: &XRPLAccountId,
    message: &HexBinary,
) -> Result<[u8; 32], ContractError> {

    let unsigned_tx_hash: [u8; 32] = Sha256::digest(message.as_slice()).into();
    let encoded_unsigned_tx_to_sign = XRPLUnsignedTxToSign {
        unsigned_tx: message,
        unsigned_tx_hash: HexTxHash::new(unsigned_tx_hash),
        cc_id: CrossChainId{source_chain: "test".try_into().unwrap(),message_id: "something".try_into().unwrap()}
    }
    .xrpl_serialize()?;
    
    Ok(xrpl_types::types::message_to_sign(
        encoded_unsigned_tx_to_sign,
        signer_xrpl_address,
    )?)
}

pub fn verify_signature(
    storage: &dyn Storage,
    multisig_session_id: &Uint64,
    public_key: &PublicKey,
    signature: &Signature,
    message: &HexBinary,
) -> StdResult<bool> {
    let signer_xrpl_address = XRPLAccountId::from(public_key);
    let tx_hash = message_to_sign(storage, multisig_session_id, &signer_xrpl_address)?;
    Ok(signature
        .verify(HexBinary::from(tx_hash), public_key)
        .is_ok())
}

pub fn proof(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    multisig_address: &Addr,
    multisig_session_id: Uint64,
) -> StdResult<ProofResponse> {
    let unsigned_tx_hash =
        MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH.load(storage, multisig_session_id.u64())?;

    let tx_info = UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &unsigned_tx_hash)?;

    let multisig: multisig::Client = client::ContractClient::new(querier, multisig_address).into();

    let multisig_session = multisig
        .multisig(multisig_session_id)
        .map_err(|_| ContractError::FailedToGetMultisigSession(multisig_session_id.u64()))?;

    let status = match multisig_session.state {
        MultisigState::Pending => ProofStatus::Pending,
        MultisigState::Completed { .. } => {
            let xrpl_signers: Vec<XRPLSigner> = multisig_session
                .optimize_signatures()
                .into_iter()
                .map(XRPLSigner::try_from)
                .collect::<Result<Vec<_>, XRPLError>>()?;

            let signed_tx = XRPLSignedTx::new(
                tx_info.unsigned_tx,
                xrpl_signers,
                HexTxHash::new(unsigned_tx_hash),
                tx_info.original_cc_id,
            );
            let execute_data = HexBinary::from(signed_tx.xrpl_serialize()?);
            ProofStatus::Completed { execute_data }
        }
    };

    Ok(ProofResponse {
        unsigned_tx_hash: HexTxHash::new(unsigned_tx_hash),
        status,
    })
}

pub fn current_verifier_set(
    storage: &dyn Storage,
) -> StdResult<Option<multisig::verifier_set::VerifierSet>> {
    CURRENT_VERIFIER_SET
        .may_load(storage)
        .map(|op| op.and_then(|set| set.try_into().ok()))
}

pub fn next_verifier_set(
    storage: &dyn Storage,
) -> StdResult<Option<multisig::verifier_set::VerifierSet>> {
    NEXT_VERIFIER_SET
        .may_load(storage)
        .map(|op| op.and_then(|set| set.try_into().ok()))
}

pub fn multisig_session(
    storage: &dyn Storage,
    cc_id: &CrossChainId,
) -> StdResult<Option<MultisigSession>> {
    CROSS_CHAIN_ID_TO_MULTISIG_SESSION.may_load(storage, cc_id)
}

pub fn ticket_create(
    storage: &dyn Storage,
    ticket_count_threshold: u32,
) -> Result<u32, ContractError> {
    let ticket_count = xrpl_multisig::num_of_tickets_to_create(storage)?;
    if ticket_count < ticket_count_threshold {
        return Err(ContractError::TicketCountThresholdNotReached);
    }

    Ok(ticket_count)
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::VerificationStatus;
    use cosmwasm_std::testing::{mock_dependencies, MockApi, MockQuerier};
    use cosmwasm_std::{HexBinary, MemoryStorage, OwnedDeps, QuerierWrapper, Uint64};
    use xrpl_types::types::{
        XRPLAccountId, XRPLSequence, XRPLTicketCreateTx, XRPLTxStatus, XRPLUnsignedTx,
    };

    use crate::msg::ProofStatus;
    use crate::state::{self, TxInfo};
    use crate::test::test_data::{self, new_verifier_set, new_xrpl_verifier_set};
    use crate::test::test_utils::{mock_querier_handler, MULTISIG_ADDRESS};

    #[derive(Clone)]
    struct SigningSession {
        pub unsigned_tx_hash: [u8; 32],
        pub session_id: Uint64,
        pub tx_info: TxInfo,
    }

    fn signing_session() -> SigningSession {
        SigningSession {
            unsigned_tx_hash: [
                109, 93, 44, 41, 175, 75, 164, 31, 73, 188, 90, 170, 17, 236, 192, 186, 108, 99,
                28, 123, 118, 231, 215, 158, 251, 130, 137, 237, 160, 82, 65, 72,
            ],
            session_id: Uint64::new(79419),
            tx_info: TxInfo {
                unsigned_tx: XRPLUnsignedTx::TicketCreate(XRPLTicketCreateTx {
                    account: XRPLAccountId::new([
                        142, 188, 192, 44, 245, 153, 112, 115, 42, 210, 53, 220, 38, 17, 131, 214,
                        213, 144, 67, 89,
                    ]),
                    fee: 165000,
                    sequence: XRPLSequence::Plain(5948774),
                    ticket_count: 6,
                }),
                status: XRPLTxStatus::Pending,
                original_cc_id: None,
            },
        }
    }

    fn setup_deps_with_signing_session(
        signing_session: SigningSession,
    ) -> OwnedDeps<MemoryStorage, MockApi, MockQuerier> {
        let mut deps = mock_dependencies();

        deps.querier.update_wasm(mock_querier_handler(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        state::UNSIGNED_TX_HASH_TO_TX_INFO
            .save(
                deps.as_mut().storage,
                &signing_session.unsigned_tx_hash,
                &signing_session.tx_info,
            )
            .unwrap();

        super::MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH
            .save(
                deps.as_mut().storage,
                signing_session.session_id.u64(),
                &signing_session.unsigned_tx_hash,
            )
            .unwrap();

        deps
    }

    #[test]
    fn next_verifier_set() {
        let mut deps = mock_dependencies();

        assert_eq!(None, super::next_verifier_set(&deps.storage).unwrap());

        state::NEXT_VERIFIER_SET
            .save(deps.as_mut().storage, &new_xrpl_verifier_set())
            .unwrap();

        assert_eq!(
            Some(new_verifier_set()),
            super::next_verifier_set(&deps.storage).unwrap()
        );
    }

    #[test]
    fn message_to_sign() {
        let signing_session = signing_session();
        let deps = setup_deps_with_signing_session(signing_session.clone());
        let signer = XRPLAccountId::new([123u8; 20]);

        let message_to_sign =
            super::message_to_sign(&deps.storage, &signing_session.session_id, &signer).unwrap();
        goldie::assert!(HexBinary::from(message_to_sign).to_string());
    }

    #[test]
    fn verify_signature() {
        let signing_session = signing_session();
        let deps = setup_deps_with_signing_session(signing_session.clone());

        let public_key = multisig::key::PublicKey::Ecdsa(
            HexBinary::from_hex(
                "02d171cb41e6765b5cdb6f5c9efc3d2477518b3698f591f31a480753b27c902a2b",
            )
            .unwrap(),
        );
        let signature: multisig::key::Signature = (multisig::key::KeyType::Ecdsa, HexBinary::from_hex("e0743ee9454a56d553c78697cafefce43f215cf800ae10e1d13f2e39aba48b3f16d677d1818bf6a7f4edda97a27bd5eff4fa6404a92e2c1c9053ebc93fd708e5").unwrap()).try_into().unwrap();

        assert!(super::verify_signature(
            &deps.storage,
            &signing_session.session_id,
            &public_key,
            &signature
        )
        .unwrap());
    }

    #[test]
    fn proof() {
        let signing_session = signing_session();
        let deps = setup_deps_with_signing_session(signing_session.clone());
        let api = deps.api;
        let multisig = api.addr_make(MULTISIG_ADDRESS);

        let proof = super::proof(
            &deps.storage,
            QuerierWrapper::new(&deps.querier),
            &multisig,
            signing_session.session_id,
        )
        .unwrap();

        assert_eq!(
            signing_session.unsigned_tx_hash,
            proof.unsigned_tx_hash.tx_hash
        );
        if let ProofStatus::Completed { execute_data } = proof.status {
            goldie::assert!(execute_data.to_string());
        } else {
            panic!("Expected ProofStatus::Completed");
        };
    }
}
