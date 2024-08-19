use std::collections::HashMap;

use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Order, StdResult, Storage, Uint64};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, UniqueIndex};
use router_api::ChainName;

use crate::key::{KeyType, KeyTyped, PublicKey, Signature};
use crate::signing::SigningSession;
use crate::verifier_set::VerifierSet;
use crate::ContractError;

#[cw_serde]
pub struct Config {
    pub rewards_contract: Addr,
    pub block_expiry: nonempty::Uint64, // number of blocks after which a signing session expires
}

type VerifierSetId = str;

pub const CONFIG: Item<Config> = Item::new("config");
pub const SIGNING_SESSION_COUNTER: Item<Uint64> = Item::new("signing_session_counter");
pub const SIGNING_SESSIONS: Map<u64, SigningSession> = Map::new("signing_sessions");
// The keys represent the addresses that can start a signing session.
pub const AUTHORIZED_CALLERS: Map<&Addr, ChainName> = Map::new("authorized_callers");
pub const VERIFIER_SETS: Map<&VerifierSetId, VerifierSet> = Map::new("verifier_sets");

/// Signatures by session id and signer address
pub const SIGNATURES: Map<(u64, &str), Signature> = Map::new("signatures");

pub fn load_session_signatures(
    store: &dyn Storage,
    session_id: u64,
) -> StdResult<HashMap<String, Signature>> {
    SIGNATURES
        .prefix(session_id)
        .range(store, None, None, Order::Ascending)
        .collect()
}

pub fn save_signature(
    store: &mut dyn Storage,
    session_id: Uint64,
    signature: Signature,
    signer: &Addr,
) -> Result<Signature, ContractError> {
    SIGNATURES.update(
        store,
        (session_id.u64(), signer.as_ref()),
        |sig| -> Result<Signature, ContractError> {
            match sig {
                Some(_) => Err(ContractError::DuplicateSignature {
                    session_id,
                    signer: signer.into(),
                }),
                None => Ok(signature),
            }
        },
    )
}

pub fn verifier_set(
    store: &dyn Storage,
    verifier_set_id: &str,
) -> Result<VerifierSet, ContractError> {
    VERIFIER_SETS.load(store, verifier_set_id).map_err(|_| {
        ContractError::NoActiveVerifierSetFound {
            verifier_set_id: verifier_set_id.to_string(),
        }
    })
}

pub struct PubKeysIndexes<'a> {
    pub pub_key: UniqueIndex<'a, Vec<u8>, HexBinary>,
}

impl IndexList<HexBinary> for PubKeysIndexes<'_> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<HexBinary>> + '_> {
        let v: Vec<&dyn Index<HexBinary>> = vec![&self.pub_key];
        Box::new(v.into_iter())
    }
}

// key type is part of the key so signers can register multiple keys with different types
pub fn pub_keys<'a>() -> IndexedMap<'a, (Addr, KeyType), HexBinary, PubKeysIndexes<'a>> {
    let indexes = PubKeysIndexes {
        pub_key: UniqueIndex::new(|p| p.to_vec(), "pub_key__unique"),
    };

    IndexedMap::new("pub_keys", indexes)
}

pub fn load_pub_key(store: &dyn Storage, signer: Addr, key_type: KeyType) -> StdResult<HexBinary> {
    pub_keys().load(store, (signer, key_type))
}

pub fn save_pub_key(
    store: &mut dyn Storage,
    signer: Addr,
    pub_key: PublicKey,
) -> Result<(), ContractError> {
    if pub_keys()
        .idx
        .pub_key
        .item(store, HexBinary::from(pub_key.clone()).into())?
        .is_some()
    {
        return Err(ContractError::DuplicatePublicKey);
    }

    Ok(pub_keys().save(store, (signer, pub_key.key_type()), &pub_key.into())?)
}

#[cfg(test)]
mod tests {

    use cosmwasm_std::testing::mock_dependencies;

    use super::*;
    use crate::test::common::ecdsa_test_data;

    #[test]
    fn should_fail_if_duplicate_public_key() {
        let mut deps = mock_dependencies();
        let pub_key = HexBinary::from_hex(
            "029bb8e80670371f45508b5f8f59946a7c4dea4b3a23a036cf24c1f40993f4a1da",
        )
        .unwrap();

        // 1. Store first key
        save_pub_key(
            deps.as_mut().storage,
            Addr::unchecked("1"),
            (KeyType::Ecdsa, pub_key.clone()).try_into().unwrap(),
        )
        .unwrap();

        // 2. Fails to store the same key
        assert_eq!(
            save_pub_key(
                deps.as_mut().storage,
                Addr::unchecked("2"),
                (KeyType::Ecdsa, pub_key).try_into().unwrap(),
            )
            .unwrap_err(),
            ContractError::DuplicatePublicKey
        );

        // 3. Storing a different key succeeds
        save_pub_key(
            deps.as_mut().storage,
            Addr::unchecked("4"),
            (KeyType::Ecdsa, ecdsa_test_data::pub_key())
                .try_into()
                .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn test_save_and_load_signatures() {
        let mut deps = mock_dependencies();
        let session_id = 1u64;

        for (i, signer) in ecdsa_test_data::signers().into_iter().enumerate() {
            let signature = Signature::try_from((KeyType::Ecdsa, signer.signature)).unwrap();
            assert!(save_signature(
                deps.as_mut().storage,
                session_id.into(),
                signature.clone(),
                &signer.address
            )
            .is_ok());

            let signatures = load_session_signatures(deps.as_ref().storage, session_id).unwrap();
            assert_eq!(signatures.len(), i + 1);
        }
    }

    #[test]
    fn test_duplicate_signature() {
        let mut deps = mock_dependencies();
        let session_id = 1u64;
        let signer = ecdsa_test_data::signers().remove(0);
        let signature = Signature::try_from((KeyType::Ecdsa, signer.signature)).unwrap();

        assert!(save_signature(
            deps.as_mut().storage,
            session_id.into(),
            signature.clone(),
            &signer.address
        )
        .is_ok());

        assert_eq!(
            save_signature(
                deps.as_mut().storage,
                session_id.into(),
                signature,
                &signer.address
            )
            .unwrap_err(),
            ContractError::DuplicateSignature {
                session_id: session_id.into(),
                signer: signer.address.into(),
            }
        );
    }
}
