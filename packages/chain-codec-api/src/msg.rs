use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Empty, HexBinary};
use msgs_derive::Permissions;
use multisig::{msg::SignerWithSig, verifier_set::VerifierSet};
use multisig_prover_api::payload::Payload;

/// The instantiate message for a chain-codec contract. If you need to receive additional parameters,
/// you can extend this struct using `#[serde(flatten)]` like this:
/// ```rust
/// #[cw_serde]
/// pub struct InstantiateMsg {
///    my_custom_field: String,
///
///    #[serde(flatten)]
///    pub base: chain_codec_api::msg::InstantiateMsg,
/// }
#[cw_serde]
pub struct InstantiateMsg {
    /// An opaque value created to distinguish distinct chains that the external gateway should be initialized with.
    /// Value must be a String in hex format without `0x`, e.g. "598ba04d225cec385d1ce3cf3c9a076af803aa5c614bc0e0d176f04ac8d28f55".
    #[serde(with = "axelar_wasm_std::hex")] // (de)serialization with hex module
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub domain_separator: Hash,
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
        verifier_set: VerifierSet,
        signers: Vec<SignerWithSig>,
        payload: Payload,
    },
    /// This query must error if the address is malformed for the chain.
    /// Not erroring is interpreted as a successful validation.
    #[returns(Empty)]
    ValidateAddress { address: String },
}

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
    /// This should return a digest for identifying the payload in the `Response::data`. This is what gets signed by the verifiers.
    /// It's called by the multisig-prover contract during proof construction.
    /// You can save additional information to the contract state if needed.
    ///
    /// This can only be called by the multisig-prover contract. That might not matter for some contracts,
    /// but if your contract needs to save additional information, that is relevant.
    #[permission(Specific(multisig_prover))]
    PayloadDigest {
        signer: VerifierSet,
        payload: Payload,
        /// This field is only available if the multisig-prover contract was compiled with the `receive-payload` feature flag.
        /// Therefore, it is also feature-gated in this crate.
        /// Please note that you should validate this in some way.
        #[cfg(feature = "receive-payload")]
        payload_bytes: HexBinary,
    },
}
