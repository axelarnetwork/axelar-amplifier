use std::net::{Ipv4Addr, SocketAddrV4};

use serde::{Deserialize, Serialize};

mod endpoints;
pub mod server;

#[derive(Clone)]
pub enum MetricsMsg {
    IncBlockReceived,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Config {
    pub enabled: bool,
    pub bind_address: SocketAddrV4,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000),
        }
    }
}

impl Config {
    pub fn get_bind_addr(&self) -> Option<SocketAddrV4> {
        if self.enabled {
            Some(self.bind_address)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
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
        assert!(serialized.contains("enabled = false"));
        assert!(serialized.contains("bind_address = \"127.0.0.1:3000\""));
        let expected = "enabled = false\nbind_address = \"127.0.0.1:3000\"";
        assert_eq!(serialized.trim(), expected);
    }
}
