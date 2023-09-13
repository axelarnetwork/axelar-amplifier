use std::fmt::Display;

use enum_display_derive::Display;
use ethers::types::U64;
use serde::{Deserialize, Serialize};

pub mod error;
pub mod finalizer;
pub mod json_rpc;
pub mod verifier;

#[derive(Debug, Deserialize, Serialize, PartialEq, Hash, Eq, Clone, Display)]
pub enum ChainName {
    Ethereum,
    #[serde(untagged)]
    Other(String),
}

impl PartialEq<connection_router::types::ChainName> for ChainName {
    fn eq(&self, other: &connection_router::types::ChainName) -> bool {
        self.to_string().eq_ignore_ascii_case(&other.to_string())
    }
}

impl ChainName {
    pub fn finalizer<'a, C, H>(
        &'a self,
        rpc_client: &'a C,
        confirmation_height: H,
    ) -> Box<dyn finalizer::Finalizer + 'a>
    where
        C: json_rpc::EthereumClient + Send + Sync,
        H: Into<U64>,
    {
        match self {
            ChainName::Ethereum => Box::new(finalizer::EthereumFinalizer::new(rpc_client)),
            ChainName::Other(_) => Box::new(finalizer::PoWFinalizer::new(
                rpc_client,
                confirmation_height,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::evm::ChainName;

    #[test]
    fn chain_name_partial_eq() {
        let chain_name = ChainName::Ethereum;

        assert!(chain_name == connection_router::types::ChainName::from_str("Ethereum").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("ETHEREUM").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("ethereum").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("ethEReum").unwrap());
        assert!(chain_name != connection_router::types::ChainName::from_str("Ethereum-1").unwrap());

        let chain_name = ChainName::Other("avalanche".into());

        assert!(chain_name == connection_router::types::ChainName::from_str("Avalanche").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("AVALANCHE").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("avalanche").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("avaLAnche").unwrap());
        assert!(
            chain_name != connection_router::types::ChainName::from_str("Avalanche-2").unwrap()
        );
    }
}
