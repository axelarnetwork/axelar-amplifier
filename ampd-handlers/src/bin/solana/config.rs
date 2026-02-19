use std::time::Duration;

use ampd::url::Url;
use error_stack::{Result, ResultExt};
use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SolanaHandlerConfig {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    pub rpc_url: Url,
    #[serde(with = "humantime_serde")]
    #[serde(default = "default_rpc_timeout")]
    pub rpc_timeout: Duration,
    pub gateway_address: String,
    pub domain_separator: String,
}

fn default_rpc_timeout() -> Duration {
    Duration::from_secs(3)
}

pub fn parse_domain_separator(input: &str) -> Result<[u8; 32], Error> {
    let hex_str = input.trim_start_matches("0x");
    hex::decode(hex_str)
        .change_context(Error::DomainSeparator)?
        .try_into()
        .map_err(|v: Vec<u8>| {
            error_stack::report!(Error::DomainSeparator)
                .attach_printable(format!("expected 32 bytes, got {}", v.len()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain_separator_raw_hex() {
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let result = parse_domain_separator(hex).unwrap();
        assert_eq!(result, hex::decode(hex).unwrap().as_slice());
    }

    #[test]
    fn parse_domain_separator_with_0x_prefix() {
        let hex = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let result = parse_domain_separator(hex).unwrap();
        let expected = hex::decode(&hex[2..]).unwrap();
        assert_eq!(result, expected.as_slice());
    }

    #[test]
    fn parse_domain_separator_invalid_hex() {
        let result = parse_domain_separator("not_valid_hex!");
        assert!(result.is_err());
    }

    #[test]
    fn parse_domain_separator_wrong_length() {
        let result = parse_domain_separator("abcdef0123456789abcdef0123456789");
        assert!(result.is_err());
    }

    #[test]
    fn parse_domain_separator_empty() {
        let result = parse_domain_separator("");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_config_uses_default_rpc_timeout() {
        let json = serde_json::json!({
            "rpc_url": "https://api.devnet.solana.com",
            "gateway_address": "gtwT4uGVTYSPnTGv6rSpMheyFyczUicxVWKqdtxNGw9",
            "domain_separator": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        });

        let config: SolanaHandlerConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.rpc_timeout, Duration::from_secs(3));
    }

    #[test]
    fn deserialize_config_with_explicit_timeout() {
        let json = serde_json::json!({
            "rpc_url": "https://api.devnet.solana.com",
            "rpc_timeout": "10s",
            "gateway_address": "gtwT4uGVTYSPnTGv6rSpMheyFyczUicxVWKqdtxNGw9",
            "domain_separator": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        });

        let config: SolanaHandlerConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.rpc_timeout, Duration::from_secs(10));
        assert_eq!(
            config.gateway_address,
            "gtwT4uGVTYSPnTGv6rSpMheyFyczUicxVWKqdtxNGw9"
        );
        assert_eq!(
            config.domain_separator,
            "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }
}
