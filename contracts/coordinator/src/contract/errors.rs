use axelar_wasm_std::nonempty;
use cosmwasm_std::Addr;
use router_api::ChainName;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed to register the basic protocol contracts")]
    RegisterProtocol,
    #[error("failed to register the prover contract {0}")]
    RegisterProverContract(Addr),
    #[error("failed to register contracts for chain {0}")]
    RegisterChain(ChainName),
    #[error("failed to register deployment {0} with router")]
    RegisterDeployment(nonempty::String),
    #[error("failed to set the active verifier set for contract {0}")]
    SetActiveVerifiers(Addr),
    #[error("failed to instantiate chain contracts")]
    InstantiateChainContracts,
    #[error("main protocol contracts (e.g. the router) are not registered yet")]
    ProtocolNotRegistered,
    #[error("failed to activate verifier set")]
    VerifierSetActivationFailed,
    #[error("chain {0} is not registered")]
    ChainNotRegistered(ChainName),
    #[error("prover {0} is not registered")]
    ProverNotRegistered(Addr),
    #[error("failed to generate instantiate2 address")]
    Instantiate2Address,
    #[error("failed to instantiate core contracts")]
    InstantiateContracts,
    #[error("failed to query code info for code id {0}")]
    QueryCodeInfo(u64),
    #[error("failed to instantiate gateway")]
    InstantiateGateway,
    #[error("failed to instantiate verifier")]
    InstantiateVerifier,
    #[error("failed to instantiate prover")]
    InstantiateProver,
    #[error(
        "coordinator failed to retrieve verifier details and corresponding provers. service_name: {service_name}, verifier_address: {verifier_address}"
    )]
    VerifierDetailsWithProvers {
        service_name: String,
        verifier_address: String,
    },
    #[error("coordinator failed to retrieve chain contracts info")]
    ChainContractsInfo,
    #[error("unable to persist the main protocol contracts")]
    UnableToPersistProtocol,
    #[error("contract config before migration not found")]
    OldConfigNotFound,

    #[error("invalid address {0}")]
    InvalidAddress(Addr),
}
