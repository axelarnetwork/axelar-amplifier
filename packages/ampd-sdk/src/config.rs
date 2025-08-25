use ampd::url::Url;
use axelar_wasm_std::chain::ChainName;
use error_stack::Result;
use report::ResultExt;
use serde::{Deserialize, Serialize};

use crate::event;

pub const DEFAULT_CONFIG_FILE: &str = "config.toml";
pub const DEFAULT_CONFIG_PREFIX: &str = "HANDLER";

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
/// let config = config::Config::builder()
///              .add_source(config::File::with_name("custom_file"))
///              .build()
///              .and_then(|config| config.try_deserialize::<Config>());
/// # Ok(())
/// # }
/// ```
#[derive(Deserialize, Serialize)]
pub struct Config {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    pub ampd_url: Url,
    pub chain_name: ChainName,
    pub event_handler: event::event_handler::Config,
}

impl Config {
    /// Loads the config from the default sources.
    ///
    /// The default sources are:
    /// - `config.toml` in the current directory
    /// - `HANDLER_*` environment variables
    ///
    /// The config is deserialized from the sources into a `Config` struct.
    pub fn from_default_sources() -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .add_source(config::File::with_name(DEFAULT_CONFIG_FILE).required(false))
            .add_source(config::Environment::with_prefix(DEFAULT_CONFIG_PREFIX))
            .build()
            .and_then(|config| config.try_deserialize::<Self>())
            .into_report()
    }
}
