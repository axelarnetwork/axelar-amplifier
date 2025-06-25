mod endpoints;
pub mod server;
use std::fmt;
use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddrV4};

use serde::{Deserialize, Serialize};

use crate::types::debug::REDACTED_VALUE;

#[derive(Debug, Clone)]
pub enum MetricsMsg {
    IncBlockReceived,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    pub enabled: bool,
    pub bind_address: Option<SocketAddrV4>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000)),
        }
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Monitoring Server Config")
            .field("enabled", &self.enabled)
            .field("bind_address", &REDACTED_VALUE)
            .finish()
    }
}

impl Config {
    pub fn get_bind_addr(&self) -> Option<SocketAddrV4> {
        if self.enabled {
            self.bind_address
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    #[test]
    fn get_bind_addr_returns_address_when_enabled() {
        let config = Config {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(
            config.get_bind_addr(),
            Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000))
        );
    }

    #[test]
    fn get_bind_addr_returns_none_when_disabled() {
        let config = Config::default();
        assert_eq!(config.get_bind_addr(), None);
    }

    #[test]
    fn serde_some_address_serializes_to_string() {
        let config = Config::default();
        let serialized = toml::to_string(&config).unwrap();
        assert!(serialized.contains("bind_address = \"127.0.0.1:3000\""));
        assert!(!serialized.contains("Some("));
        println!("Serialized config with address: {}", serialized);
    }

    #[test]
    fn debug_implementation_redatcs_bind_address() {
        let config = Config::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("bind_address: \"redacted\""));
        assert!(debug_str.contains("enabled: false"));
    }
}
