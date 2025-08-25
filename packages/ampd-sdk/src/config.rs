use ampd::url::Url;
use axelar_wasm_std::chain::ChainName;
use error_stack::{Result, ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event;

pub const DEFAULT_CONFIG_FILE: &str = "config.toml";
pub const DEFAULT_CONFIG_PREFIX: &str = "HANDLER";

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to build config")]
    Build,
}

/// The config struct for the Handler
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
///              .add_file_source("custom_config.toml", true)
///              .add_env_source("HANDLER")
///              .build();
/// # Ok(())
/// # }
/// ```
#[derive(Deserialize, Serialize)]
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
    /// The default sources are:
    /// - `config.toml` in the current directory
    /// - `HANDLER_*` environment variables
    ///
    /// The config is deserialized from the sources into a `Config` struct.
    pub fn from_default_sources() -> Result<Self, Error> {
        Self::builder()
            .add_file_source(DEFAULT_CONFIG_FILE, false)
            .add_env_source(DEFAULT_CONFIG_PREFIX)
            .build()
    }
}

pub struct ConfigBuilder(config::ConfigBuilder<config::builder::DefaultState>);

impl ConfigBuilder {
    pub fn new() -> Self {
        Self(config::Config::builder())
    }

    /// Adds a source to the config builder.
    pub fn add_source<T>(self, source: T) -> Self
    where
        T: config::Source + Send + Sync + 'static,
    {
        Self(self.0.add_source(source))
    }

    /// Adds a file source to the config builder.
    pub fn add_file_source(self, base_file: &str, required: bool) -> Self {
        Self(
            self.0
                .add_source(config::File::with_name(base_file).required(required)),
        )
    }

    /// Adds an environment source with the given prefix to the config builder.
    /// For example, if the prefix is "HANDLER", the environment variable HANDLER_AMPD_URL
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
