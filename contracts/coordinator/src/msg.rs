use std::collections::{BTreeMap, HashSet};

use axelar_wasm_std::address::AddressFormat;
use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::{nonempty, MajorityThreshold};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Binary};
use msgs_derive::Permissions;
use multisig::key::KeyType;
use router_api::ChainName;
use serde_json::Value;
use service_registry_api::Verifier;

pub use crate::contract::MigrateMsg;

type ProverAddress = Addr;
type GatewayAddress = Addr;
type VerifierAddress = Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
}

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
    /// After the contract is instantiated, this should be the first call to execute
    #[permission(Governance)]
    RegisterProtocol {
        service_registry_address: String,
        router_address: String,
        multisig_address: String,
    },
    #[permission(Governance)]
    RegisterChain {
        chain_name: ChainName,
        prover_address: String,
        gateway_address: String,
        voting_verifier_address: String,
    },
    #[permission(Specific(prover))]
    SetActiveVerifiers { verifiers: HashSet<String> },

    #[permission(Governance)]
    InstantiateChainContracts {
        deployment_name: nonempty::String,
        salt: Binary,
        // Make params a Box to avoid having a large discrepancy in variant sizes
        // Such an error will be flagged by "cargo clippy..."
        params: Box<DeploymentParams>,
    },

    /// `RegisterDeployment` calls the router using `ExecuteMsgFromProxy`.
    /// The router will enforce that the original sender has
    /// permission to register the deployment.
    #[permission(Governance)]
    RegisterDeployment { deployment_name: nonempty::String },
}

#[cw_serde]
pub struct ContractDeploymentInfo<T> {
    pub code_id: u64,
    pub label: String,
    pub msg: T,
}

#[cw_serde]
pub struct ManualDeploymentParams {
    pub gateway: ContractDeploymentInfo<()>,
    pub chain_codec: ContractDeploymentInfo<Extended<ChainCodecMsg>>,
    pub verifier: ContractDeploymentInfo<VerifierMsg>,
    pub prover: ContractDeploymentInfo<ProverMsg>,
}

#[cw_serde]
// The parameters used to configure each instantiation.
// This is an enum to allow for additional parameter types in the future
pub enum DeploymentParams {
    Manual(ManualDeploymentParams), // user supplies all info that cannot be inferred by coordinator
}

#[cw_serde]
pub struct ProverMsg {
    pub governance_address: String,
    pub multisig_address: String,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub key_type: KeyType,
    pub sig_verifier_address: Option<String>,
}

#[cw_serde]
pub struct VerifierMsg {
    pub governance_address: nonempty::String,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: nonempty::Uint64,
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_address: nonempty::String,
    pub msg_id_format: MessageIdFormat,
    pub address_format: AddressFormat,
}

/// Allows adding additional fields to a message's JSON that are not known at compile time.
///
/// # Example
///
/// ```rust
/// # use cosmwasm_schema::cw_serde;
/// # use coordinator::msg::Extended;
///
/// #[cw_serde]
/// struct Person {
///     name: String,
///     age: u8,
/// }
/// let data = r#"
///     {
///         "name": "John Doe",
///         "age": 43,
///         "phone": "+44 1234567"
///     }"#;
///
/// // Parse the data into Extended<Person>.
/// let v: Extended<Person> = serde_json::from_str(data)?;
/// let json = serde_json::to_string(&v)?;
///
/// assert_eq!(v.inner.name, "John Doe");
/// assert_eq!(v.inner.age, 43);
/// assert_eq!(v.additional.get("phone").unwrap().as_str(), Some("+44 1234567"));
///
/// # Ok::<(), serde_json::Error>(())
/// ```
#[cw_serde]
pub struct Extended<T> {
    #[serde(flatten)]
    pub inner: T,
    /// Additional fields that are not known at compile time.
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

impl<T> Extended<T> {
    pub fn new(inner: T, additional: BTreeMap<String, Value>) -> Self {
        Extended { inner, additional }
    }
}

impl<T> From<T> for Extended<T> {
    fn from(inner: T) -> Self {
        Extended::new(inner, BTreeMap::new())
    }
}

#[cw_serde]
pub struct ChainCodecMsg {
    #[serde(with = "axelar_wasm_std::hex")] // (de)serialization with hex module
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub domain_separator: Hash,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(bool)]
    ReadyToUnbond { verifier_address: String },

    #[returns(VerifierInfo)]
    VerifierInfo {
        service_name: String,
        verifier: String,
    },

    #[returns(ChainContractsResponse)]
    ChainContractsInfo(ChainContractsKey),
}

#[cw_serde]
pub struct VerifierInfo {
    pub verifier: Verifier,
    pub weight: nonempty::Uint128,
    pub supported_chains: Vec<ChainName>,
    pub actively_signing_for: Vec<Addr>,
}

#[cw_serde]
pub enum ChainContractsKey {
    ChainName(ChainName),
    ProverAddress(ProverAddress),
    GatewayAddress(GatewayAddress),
    VerifierAddress(VerifierAddress),
}

#[cw_serde]
pub struct ChainContractsResponse {
    pub chain_name: ChainName,
    pub prover_address: ProverAddress,
    pub gateway_address: GatewayAddress,
    pub verifier_address: VerifierAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cw_serde]
    struct Person {
        name: String,
        age: u8,
    }

    #[cw_serde]
    struct ExtendedPerson {
        #[serde(flatten)]
        pub inner: Person,
        /// additional field known at compile time
        pub phone: String,
    }

    #[test]
    fn test_extended() {
        let inner = Person {
            name: "John Doe".into(),
            age: 43,
        };
        let mut additional = BTreeMap::new();
        additional.insert("phone".into(), "+44 1234567".into());

        let extended: Extended<Person> = Extended::new(inner, additional);

        // make sure the JSON can be deserialized into Person
        let json = serde_json::to_string(&extended).unwrap();
        let deserialized: Person = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, "John Doe");
        assert_eq!(deserialized.age, 43);
    }

    #[test]
    fn test_extended_to_custom() {
        let original = Person {
            name: "Jane Doe".into(),
            age: 30,
        };
        let mut additional = BTreeMap::new();
        additional.insert("phone".into(), "+44 1234567".into());

        let extended: Extended<Person> = Extended::new(original, additional);

        // make sure the JSON can be deserialized into ExtendedPerson
        let json = serde_json::to_string(&extended).unwrap();
        let deserialized: ExtendedPerson = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.inner.name, "Jane Doe");
        assert_eq!(deserialized.inner.age, 30);
        assert_eq!(deserialized.phone, "+44 1234567");
    }
}
