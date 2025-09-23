use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Empty, HexBinary};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use multisig_prover_api::payload::Payload;

/// The instantiate message for a chain-codec contract. If you need to receive additional parameters,
/// you can extend this struct using `#[serde(flatten)]` like this:
/// ```rust
/// # use cosmwasm_schema::cw_serde;
///
/// #[cw_serde]
/// pub struct InstantiateMsg {
///    my_custom_field: String,
///
///    #[serde(flatten)]
///    pub base: chain_codec_api::msg::InstantiateMsg,
/// }
#[cw_serde]
pub struct InstantiateMsg {
    /// The multisig prover contract address.
    /// This is used for access control.
    pub multisig_prover: String,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Encodes the execute data for the target chain that the relayer will submit.
    #[returns(HexBinary)]
    EncodeExecData {
        /// An opaque value created to distinguish distinct chains that the external gateway should be initialized with.
        #[serde(with = "axelar_wasm_std::hex")]
        #[schemars(with = "String")]
        domain_separator: Hash,
        verifier_set: VerifierSet,
        signers: Vec<SignerWithSig>,
        payload: Payload,
    },
    /// This query must error if the address is malformed for the chain.
    /// Not erroring is interpreted as a successful validation.
    #[returns(Empty)]
    ValidateAddress { address: String },
    /// This query returns a digest for identifying the payload. This is what gets signed by the verifiers.
    /// It's called by the multisig-prover contract during proof construction.
    #[returns(HexBinary)]
    PayloadDigest {
        /// An opaque value created to distinguish distinct chains that the external gateway should be initialized with.
        #[serde(with = "axelar_wasm_std::hex")]
        #[schemars(with = "String")]
        domain_separator: Hash,
        verifier_set: VerifierSet,
        payload: Payload,
        /// This field is only available if the multisig-prover contract received the full message payloads and
        /// if the digest is for proof construction. For a verifier set update or if the multisig-prover contract
        /// did not receive the full message payloads, it is empty.
        full_message_payloads: Vec<HexBinary>,
    },
}

#[cw_serde]
#[derive(msgs_derive::Permissions)]
pub enum ExecuteMsg {
    /// This message is called by the multisig-prover contract after a multisig session is started.
    /// It provides session information that the chain codec contract can store and use later.
    /// The contract can also still revert the transaction here by returning an error or panicking.
    ///
    /// This can only be called by the multisig-prover contract.
    ///
    /// This field is only available if the multisig-prover contract was compiled with the `notify-signing-session` feature flag.
    /// Therefore, it is also feature-gated in this crate.
    #[permission(Specific(multisig_prover))]
    NotifySigningSession {
        /// An opaque value created to distinguish distinct chains that the external gateway should be initialized with.
        #[serde(with = "axelar_wasm_std::hex")]
        #[schemars(with = "String")]
        domain_separator: Hash,
        multisig_session_id: cosmwasm_std::Uint64,
        verifier_set: VerifierSet,
        payload: Payload,
        /// This field is only filled if the multisig-prover contract received the full message payloads and
        /// if the session is for proof construction. For a verifier set update, it is empty.
        full_message_payloads: Vec<HexBinary>,
    },
}
