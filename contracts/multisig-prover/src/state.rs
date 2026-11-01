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
    #[serde(default)]
    pub sig_verifier_address: Option<Addr>,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const PAYLOAD: Map<&PayloadId, Payload> = Map::new("payload");
pub const MULTISIG_SESSION_PAYLOAD: Map<u64, PayloadId> = Map::new("multisig_session_payload");

// we only need to save full message payloads if both the `notify-signing-session` and `receive-payload`
// features are enabled
pub const FULL_MESSAGE_PAYLOADS: Map<&PayloadId, Vec<HexBinary>> =
    Map::new("full_message_payloads");

pub const REPLY_TRACKER: Item<PayloadId> = Item::new("reply_tracker");

pub const CURRENT_VERIFIER_SET: Item<VerifierSet> = Item::new("current_verifier_set");
pub const NEXT_VERIFIER_SET: Item<VerifierSet> = Item::new("next_verifier_set");

#[cfg(test)]
mod tests {
    use axelar_wasm_std::{MajorityThreshold, Threshold};
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Addr;
    use router_api::{chain_name, cosmos_addr};

    use super::*;

    /// Layout of `Config` as stored by provers released without `sig_verifier_address`
    /// (multisig-prover 1.2.1).
    #[cw_serde]
    struct ConfigWithoutSigVerifierAddress {
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

    /// Same key as CONFIG so we can write the field-less layout and read it with the current type.
    const CONFIG_WITHOUT_SIG_VERIFIER_ADDRESS: Item<ConfigWithoutSigVerifierAddress> =
        Item::new("config");

    /// Regression test: `sig_verifier_address` was removed from `Config` in #1141 and restored
    /// afterwards. Contracts deployed from a release without the field must keep loading their
    /// stored config, with the field reading as `None`.
    #[test]
    fn loads_state_stored_without_sig_verifier_address() {
        let mut deps = mock_dependencies();

        let stored = ConfigWithoutSigVerifierAddress {
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
        };

        CONFIG_WITHOUT_SIG_VERIFIER_ADDRESS
            .save(deps.as_mut().storage, &stored)
            .unwrap();

        let loaded = CONFIG
            .load(deps.as_ref().storage)
            .expect("current code must load config stored without sig_verifier_address");

        assert_eq!(loaded.sig_verifier_address, None);
        assert_eq!(loaded.gateway, stored.gateway);
        assert_eq!(loaded.multisig, stored.multisig);
        assert_eq!(loaded.service_name, stored.service_name);
        assert_eq!(loaded.chain_name, stored.chain_name);
        assert_eq!(
            loaded.verifier_set_diff_threshold,
            stored.verifier_set_diff_threshold
        );
        assert_eq!(loaded.notify_signing_session, stored.notify_signing_session);
        assert_eq!(
            loaded.expect_full_message_payloads,
            stored.expect_full_message_payloads
        );
    }
}
