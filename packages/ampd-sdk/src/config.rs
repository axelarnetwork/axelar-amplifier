use ampd::url::Url;
use axelar_wasm_std::chain::ChainName;
use error_stack::{Report, Result, ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event;

pub const DEFAULT_CONFIG_FILE: &str = "config.toml";
pub const DEFAULT_CONFIG_PREFIX: &str = "AMPD_HANDLERS";

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to build config")]
    Build,
}

/// The config struct used by handlers to manage connections to the ampd gRPC server
///
/// # Examples
///
/// ## From default sources
/// ```rust
/// # use ampd_sdk::config::Config;
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let config = Config::from_default_sources();
/// # Ok(())
/// # }
/// ```
///
/// ## From custom sources
/// ```rust
/// # use ampd_sdk::config::Config;
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let config = Config::builder()
///     .add_file_source("custom_config.toml", true)
///     .add_env_source("MY_HANDLER")
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Using `config` crate
/// ```rust
/// # use ampd_sdk::config::Config;
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let config = config::Config::builder()
///     .add_source(config::File::with_name("custom_config.toml").required(false))
///     .add_source(config::Environment::with_prefix("MY_HANDLER"))
///     .build()?;
/// let config = Config::try_from(config);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    pub ampd_url: Url,
    pub chain_name: ChainName,
    #[serde(default)]
    pub event_handler: event::event_handler::Config,
}

impl Config {
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Loads the config from the default sources.
    ///
    /// The default sources are added in the following order:
    /// - `config.toml` in the current directory
    /// - `AMPD_HANDLERS_*` environment variables
    ///
    /// Configuration loaded from the environment variables will override the configuration loaded from the file.
    ///
    /// The config is deserialized from the sources into a `Config` struct.
    pub fn from_default_sources() -> Result<Self, Error> {
        Self::builder()
            .add_file_source(DEFAULT_CONFIG_FILE, false)
            .add_env_source(DEFAULT_CONFIG_PREFIX)
            .build()
    }
}

impl TryFrom<config::Config> for Config {
    type Error = Report<Error>;

    fn try_from(config: config::Config) -> Result<Config, Error> {
        config
            .try_deserialize::<Config>()
            .change_context(Error::Build)
    }
}

/// Configuration builder used to construct a `Config` struct.
///
/// The order in which the sources are added is important. If a field is set in multiple sources,
/// the last added source will override the previous ones.
#[derive(Default)]
pub struct ConfigBuilder(config::ConfigBuilder<config::builder::DefaultState>);

impl ConfigBuilder {
    fn new() -> Self {
        Self(config::Config::builder())
    }

    /// Adds a file source to the config builder.
    pub fn add_file_source(self, base_file: &str, required: bool) -> Self {
        Self(
            self.0
                .add_source(config::File::with_name(base_file).required(required)),
        )
    }

    /// Adds an environment source with the given prefix to the config builder.
    /// For example, if the prefix is "AMPD_HANDLERS", the environment variable AMPD_HANDLERS_AMPD_URL
    /// will be used to set the ampd_url field in the config.
    pub fn add_env_source(self, prefix: &str) -> Self {
        Self(self.0.add_source(config::Environment::with_prefix(prefix)))
    }

    /// Builds the config from the sources.
    ///
    /// The config is deserialized from the sources into a `Config` struct.
    pub fn build(self) -> Result<Config, Error> {
        self.0
            .build()
            .and_then(|config| config.try_deserialize::<Config>())
            .change_context(Error::Build)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::str::FromStr;

    use axelar_wasm_std::assert_err_contains;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn config_loads_from_default_sources() {
        let ampd_url = "http://localhost:8080";
        let chain_name = "some-chain";

        temp_env::with_vars(
            vec![
                (format!("{DEFAULT_CONFIG_PREFIX}_AMPD_URL"), Some(ampd_url)),
                (
                    format!("{DEFAULT_CONFIG_PREFIX}_CHAIN_NAME"),
                    Some(chain_name),
                ),
            ],
            || {
                let config = Config::from_default_sources().unwrap();

                assert_eq!(config.ampd_url, Url::new_sensitive(ampd_url).unwrap());
                assert_eq!(config.chain_name, ChainName::from_str(chain_name).unwrap());
            },
        );
    }

    #[test]
    fn config_loads_from_custom_env_vars() {
        let ampd_url = "http://localhost:8080";
        let chain_name = "some-chain";
        let prefix = "MY_HANDLER";

        temp_env::with_vars(
            vec![
                (format!("{prefix}_AMPD_URL"), Some(ampd_url)),
                (format!("{prefix}_CHAIN_NAME"), Some(chain_name)),
            ],
            || {
                let config = Config::builder().add_env_source(prefix).build().unwrap();

                assert_eq!(config.ampd_url, Url::new_sensitive(ampd_url).unwrap());
                assert_eq!(config.chain_name, ChainName::from_str(chain_name).unwrap());
            },
        );
    }

    #[test]
    fn config_loads_from_custom_file() {
        let ampd_url = "http://localhost:8080";
        let chain_name = "some-chain";

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("custom-config.toml");
        let content = format!(
            r#"
            ampd_url="{ampd_url}"
            chain_name="{chain_name}"
            "#
        );
        fs::write(&config_path, content).unwrap();

        let config = Config::builder()
            .add_file_source(config_path.to_str().unwrap(), true)
            .build()
            .unwrap();

        assert_eq!(config.ampd_url, Url::new_sensitive(ampd_url).unwrap());
        assert_eq!(config.chain_name, ChainName::from_str(chain_name).unwrap());
    }

    #[test]
    fn config_load_fails_if_field_is_missing() {
        let ampd_url = "http://localhost:8080";

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("custom-config.toml");
        let content = format!(
            r#"
            ampd_url="{ampd_url}"
            "#
        );
        fs::write(&config_path, content).unwrap();

        let res = Config::builder()
            .add_file_source(config_path.to_str().unwrap(), true)
            .build();

        assert_err_contains!(res, Error, Error::Build);
    }
}
