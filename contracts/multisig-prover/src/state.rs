use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary};
use cw_storage_plus::{Item, Map};
use multisig::key::KeyType;
use multisig::verifier_set::VerifierSet;
use multisig_prover_api::payload::{Payload, PayloadId};
use router_api::ChainName;

#[cw_serde]
pub struct Config {
    pub gateway: Addr,
    pub multisig: Addr,
    pub coordinator: Addr,
    pub service_registry: Addr,
    pub voting_verifier: Addr,
    pub chain_codec: Addr,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub key_type: KeyType,
    pub domain_separator: Hash,
    pub notify_signing_session: bool,
    pub expect_full_message_payloads: bool,
}

pub const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
mod tests {

    use axelar_wasm_std::{MajorityThreshold, Threshold};
    use cosmwasm_std::{testing::mock_dependencies, Addr};
    use router_api::{chain_name, cosmos_addr};

    use super::*;

    /// Old layout of Config with sig_verifier_address
    #[cw_serde]
    struct LegacyConfig {
        pub gateway: Addr,
        pub multisig: Addr,
        pub coordinator: Addr,
        pub service_registry: Addr,
        pub voting_verifier: Addr,
        pub chain_codec: Addr,
        pub signing_threshold: MajorityThreshold,
        pub service_name: String,
        pub chain_name: ChainName,
        pub verifier_set_diff_threshold: u32,
        pub key_type: KeyType,
        pub domain_separator: Hash,
        pub notify_signing_session: bool,
        pub expect_full_message_payloads: bool,
        pub sig_verifier_address: Option<String>,
    }

    /// Same key as CONFIG so we can write "old" state and read with current type.
    const LEGACY_CONFIG: Item<LegacyConfig> = Item::new("config");

    #[test]
    fn loads_old_state_with_sig_verifier_address() {
        let mut deps = mock_dependencies();

        let legacy = LegacyConfig {
            gateway: cosmos_addr!("cosmos1gateway"),
            multisig: cosmos_addr!("cosmos1multisig"),
            coordinator: cosmos_addr!("cosmos1coordinator"),
            service_registry: cosmos_addr!("cosmos1serviceregistry"),
            voting_verifier: cosmos_addr!("cosmos1votingverifier"),
            chain_codec: cosmos_addr!("cosmos1chaincodec"),
            signing_threshold: Threshold::try_from((2u64, 3u64))
                .unwrap()
                .try_into()
                .unwrap(),
            service_name: "validators".to_string(),
            chain_name: chain_name!("ethereum"),
            verifier_set_diff_threshold: 0,
            key_type: KeyType::Ecdsa,
            domain_separator: [0u8; 32],
            notify_signing_session: false,
            expect_full_message_payloads: false,
            sig_verifier_address: Some("cosmos1oldverifier".to_string()),
        };

        LEGACY_CONFIG.save(deps.as_mut().storage, &legacy).unwrap();

        let loaded = CONFIG
            .load(deps.as_ref().storage)
            .expect("new code must load state saved with old (sig_verifier_address) layout");

        assert_eq!(loaded.gateway, legacy.gateway);
        assert_eq!(loaded.multisig, legacy.multisig);
        assert_eq!(loaded.service_name, legacy.service_name);
        assert_eq!(loaded.chain_name, legacy.chain_name);
        assert_eq!(loaded.verifier_set_diff_threshold, legacy.verifier_set_diff_threshold);
        assert_eq!(loaded.notify_signing_session, legacy.notify_signing_session);
        assert_eq!(loaded.expect_full_message_payloads, legacy.expect_full_message_payloads);
    }
}

pub const PAYLOAD: Map<&PayloadId, Payload> = Map::new("payload");
pub const MULTISIG_SESSION_PAYLOAD: Map<u64, PayloadId> = Map::new("multisig_session_payload");

// we only need to save full message payloads if both the `notify-signing-session` and `receive-payload`
// features are enabled
pub const FULL_MESSAGE_PAYLOADS: Map<&PayloadId, Vec<HexBinary>> =
    Map::new("full_message_payloads");

pub const REPLY_TRACKER: Item<PayloadId> = Item::new("reply_tracker");

pub const CURRENT_VERIFIER_SET: Item<VerifierSet> = Item::new("current_verifier_set");
pub const NEXT_VERIFIER_SET: Item<VerifierSet> = Item::new("next_verifier_set");
