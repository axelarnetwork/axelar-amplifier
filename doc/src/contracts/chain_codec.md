# Chain codec contract

The chain codec contract encapsulates chain-specific functionality that is needed in the multisig prover and voting verifier.
It provides messages / queries for encoding and hashing payloads, as well as verifying addresses.

New chain integrations should try to implement this contract and reuse the existing multisig-prover and voting-verifier contracts in order to minimize code duplication.
If that is not an option, forking the multisig-prover and voting-verifier contracts may be necessary.

## Interface

These interface types are defined in the `chain-codec-api` crate. It is recommended to use this crate in your chain-codec contract instead of copying the code.

```Rust
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
    /// An opaque value created to distinguish distinct chains that the external gateway should be initialized with.
    /// Value must be a String in hex format without `0x`, e.g. "598ba04d225cec385d1ce3cf3c9a076af803aa5c614bc0e0d176f04ac8d28f55".
    #[serde(with = "axelar_wasm_std::hex")] // (de)serialization with hex module
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub domain_separator: Hash,
    /// The multisig prover contract address.
    /// This is used for access control.
    pub multisig_prover: String,
}

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
        /// This field is only available if the multisig-prover contract was instantiated with the `receive-payload` flag enabled.
        /// Therefore, it is also feature-gated in this crate.
        /// This is only filled if the digest is for proof construction. For a verifier set update, it is empty.
        /// Please note that you should validate this in some way.
        #[cfg(feature = "receive-payload")]
        full_message_payloads: Vec<HexBinary>,
    },
}

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
```

Any implementation should provide the above mentioned messages / queries.
You can find simple example implementations for EVM chains and Sui in the `contracts/chain-codec-*` directories.
