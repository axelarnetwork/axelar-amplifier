use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Empty, HexBinary};
use multisig::{msg::SignerWithSig, verifier_set::VerifierSet};
use multisig_prover_api::payload::Payload;

pub type InstantiateMsg = Empty;

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Returns a digest for identifying a payload. This is what gets signed by the verifiers.
    #[returns(Hash)]
    PayloadDigest {
        domain_separator: Hash,
        signer: VerifierSet,
        payload: Payload,
    },
    /// Encodes the execute data for the target chain that the relayer will submit.
    #[returns(HexBinary)]
    EncodeExecData {
        domain_separator: Hash,
        verifier_set: VerifierSet,
        signers: Vec<SignerWithSig>,
        payload: Payload,
    },
    /// Returns `true` iff the given address is formatted as a valid address on the chain.
    /// An error should be considered a failure to validate the address.
    #[returns(bool)]
    ValidateAddress {
        address: String,
    }
}