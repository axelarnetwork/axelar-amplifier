use cosmwasm_std::Addr;
use lazy_static::lazy_static;

use crate::{
    address, chain_name, chain_name_raw, cosmos_addr, cosmos_address, Address, ChainName,
    ChainNameRaw,
};

lazy_static! {
    pub static ref DESTINATION_ADDRESS: Address = address!("destination-address");
    pub static ref SOURCE_ADDRESS: Address = address!("source-address");
    pub static ref AVALANCHE_CHAIN_NAME: ChainName = chain_name!("avalanche");
    pub static ref AXELAR_CHAIN_NAME: ChainName = chain_name!("axelar");
    pub static ref AXELARNET_CHAIN_NAME: ChainName = chain_name!("axelarnet");
    pub static ref BITCOIN_CHAIN_NAME: ChainName = chain_name!("bitcoin");
    pub static ref DESTINATION_CHAIN_NAME: ChainName = chain_name!("destination-chain");
    pub static ref ETHEREUM_CHAIN_NAME: ChainName = chain_name!("ethereum");
    pub static ref MOCK_CHAIN_NAME: ChainName = chain_name!("mock-chain");
    pub static ref MULTIVERSX_CHAIN_NAME: ChainName = chain_name!("multiversx");
    pub static ref POLYGON_CHAIN_NAME: ChainName = chain_name!("polygon");
    pub static ref SOLANA_CHAIN_NAME: ChainName = chain_name!("solana");
    pub static ref SOURCE_CHAIN_NAME: ChainName = chain_name!("source-chain");
    pub static ref STACKS_CHAIN_NAME: ChainName = chain_name!("stacks");
    pub static ref STARKNET_CHAIN_NAME: ChainName = chain_name!("starknet");
    pub static ref STELLAR_CHAIN_NAME: ChainName = chain_name!("stellar");
    pub static ref SUI_CHAIN_NAME: ChainName = chain_name!("sui");
    pub static ref XRPL_CHAIN_NAME: ChainName = chain_name!("xrpl");
    pub static ref AVALANCHE_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("avalanche");
    pub static ref AXELAR_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("axelar");
    pub static ref DESTINATION_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("destinationchain");
    pub static ref ETHEREUM_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("ethereum");
    pub static ref POLYGON_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("polygon");
    pub static ref SOLANA_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("solana");
    pub static ref SOURCE_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("sourcechain");
    pub static ref STELLAR_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("stellar");
    pub static ref SUI_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("sui");
    pub static ref XRPL_CHAIN_NAME_RAW: ChainNameRaw = chain_name_raw!("xrpl");
    pub static ref ADMIN_COSMOS_ADDR: Addr = cosmos_addr!("admin");
    pub static ref AXELARNET_GATEWAY_COSMOS_ADDR: Addr = cosmos_addr!("axelarnet-gateway");
    pub static ref COORDINATOR_COSMOS_ADDR: Addr = cosmos_addr!("coordinator");
    pub static ref GATEWAY_COSMOS_ADDR: Addr = cosmos_addr!("gateway");
    pub static ref GOVERNANCE_COSMOS_ADDR: Addr = cosmos_addr!("governance");
    pub static ref INSTANTIATOR_COSMOS_ADDR: Addr = cosmos_addr!("instantiator");
    pub static ref MULTISIG_COSMOS_ADDR: Addr = cosmos_addr!("multisig");
    pub static ref NEXUS_COSMOS_ADDR: Addr = cosmos_addr!("nexus");
    pub static ref OPERATOR_COSMOS_ADDR: Addr = cosmos_addr!("operator");
    pub static ref PROVER_COSMOS_ADDR: Addr = cosmos_addr!("prover");
    pub static ref RELAYER_COSMOS_ADDR: Addr = cosmos_addr!("relayer");
    pub static ref REWARDS_COSMOS_ADDR: Addr = cosmos_addr!("rewards");
    pub static ref ROUTER_COSMOS_ADDR: Addr = cosmos_addr!("router");
    pub static ref SENDER_COSMOS_ADDR: Addr = cosmos_addr!("sender");
    pub static ref SERVICE_REGISTRY_COSMOS_ADDR: Addr = cosmos_addr!("service_registry");
    pub static ref VERIFIER_COSMOS_ADDR: Addr = cosmos_addr!("verifier");
    pub static ref VOTING_VERIFIER_COSMOS_ADDR: Addr = cosmos_addr!("voting_verifier");
    pub static ref TRANSLATION_COSMOS_ADDRESS: Address = cosmos_address!("translation");
    pub static ref TRANSLATION_CONTRACT_COSMOS_ADDRESS: Address =
        cosmos_address!("translation_contract");
}
