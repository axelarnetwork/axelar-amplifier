use std::marker::PhantomData;
use std::path::PathBuf;

use ampd::monitoring;
use ampd::url::Url;
use axelar_wasm_std::chain::ChainName;
use config as cfg;
use error_stack::{Report, Result, ResultExt};
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::deserialize_default_from_empty_object;
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
/// # use std::path::PathBuf;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let config = Config::from_default_sources(PathBuf::from("./"));
/// # Ok(())
/// # }
/// ```
///
/// ## From custom sources
/// ```rust
/// # use ampd_sdk::config::builder;
/// # use ampd_sdk::config::Config;
/// # use std::error::Error;
/// # use std::path::PathBuf;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let config = builder::<Config>()
///     .add_file_source(PathBuf::from("custom_config.toml"))
///     .add_env_source("MY_HANDLER")
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Using `config` crate
/// ```rust
/// # use ampd_sdk::config::Config;
/// # use config as cfg;
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let config = cfg::Config::builder()
///     .add_source(cfg::File::with_name("custom_config.toml").required(false))
///     .add_source(cfg::Environment::with_prefix("MY_HANDLER"))
///     .build()?;
/// let config = Config::try_from(config);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    #[serde(default = "default_ampd_url")]
    pub ampd_url: Url,
    pub chain_name: ChainName,

    // Using `serde_aux` to be able to use `default` together with `flatten`. See https://github.com/serde-rs/serde/issues/1626
    #[serde(flatten, deserialize_with = "deserialize_default_from_empty_object")]
    pub event_handler: event::event_handler::Config,

    #[serde(default)]
    pub monitoring_server: monitoring::Config,
}

fn default_ampd_url() -> Url {
    Url::new_sensitive("http://127.0.0.1:9090").expect("Url should be created validly")
}

impl Config {
    /// Loads the config from the default sources in the given directory.
    ///
    /// The default sources are added in the following order:
    /// - `config.toml` in the given directory
    /// - `AMPD_HANDLERS_*` environment variables
    ///
    /// Configuration loaded from the environment variables will override the configuration loaded from the file.
    ///
    /// The config is deserialized from the sources into a `Config` struct.
    pub fn from_default_sources(dir: PathBuf) -> Result<Self, Error> {
        builder()
            .add_file_source(dir.join(DEFAULT_CONFIG_FILE))
            .add_env_source(DEFAULT_CONFIG_PREFIX)
            .build()
    }
}

impl TryFrom<cfg::Config> for Config {
    type Error = Report<Error>;

    fn try_from(config: cfg::Config) -> Result<Config, Error> {
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
pub struct ConfigBuilder<T> {
    inner: cfg::ConfigBuilder<cfg::builder::DefaultState>,
    _phantom: PhantomData<T>,
}

impl<T> ConfigBuilder<T> {
    /// Adds a file source to the config builder.
    pub fn add_file_source(self, base_file: PathBuf) -> Self {
        Self {
            inner: self
                .inner
                .add_source(cfg::File::from(base_file).required(false)),
            _phantom: self._phantom,
        }
    }

    /// Adds an environment source with the given prefix to the config builder.
    /// For example, if the prefix is "AMPD_HANDLERS", the environment variable AMPD_HANDLERS_AMPD_URL
    /// will be used to set the ampd_url field in the config.
    pub fn add_env_source(self, prefix: &str) -> Self {
        Self {
            inner: self.inner.add_source(cfg::Environment::with_prefix(prefix)),
            _phantom: self._phantom,
        }
    }

    /// Builds the config from the sources.
    ///
    /// The config is deserialized from the sources into a `Config` struct.
    pub fn build(self) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.inner
            .build()
            .and_then(|config| config.try_deserialize::<T>())
            .change_context(Error::Build)
    }
}

pub fn builder<T>() -> ConfigBuilder<T> {
    ConfigBuilder {
        inner: cfg::Config::builder(),
        _phantom: PhantomData,
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
                let config = Config::from_default_sources(PathBuf::from("./")).unwrap();

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
                let config = builder::<Config>().add_env_source(prefix).build().unwrap();

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

        let config = builder::<Config>()
            .add_file_source(config_path)
            .build()
            .unwrap();

        assert_eq!(config.ampd_url, Url::new_sensitive(ampd_url).unwrap());
        assert_eq!(config.chain_name, ChainName::from_str(chain_name).unwrap());
    }

    #[tokio::test]
    async fn config_loads_from_file_can_be_used_concurrently() {
        let ampd_url = "http://localhost:8080";
        let chain_name = "some-chain";
        let concurrent_tasks = 1000;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("custom-config.toml");
        let content = format!(
            r#"
            ampd_url="{ampd_url}"
            chain_name="{chain_name}"
            "#
        );
        fs::write(&config_path, content).unwrap();

        let handles = (0..concurrent_tasks)
            .map(|_| {
                let config_path_clone = config_path.clone();

                tokio::spawn(async move {
                    let config = builder::<Config>()
                        .add_file_source(config_path_clone)
                        .build()
                        .unwrap();

                    assert_eq!(config.ampd_url, Url::new_sensitive(ampd_url).unwrap());
                    assert_eq!(config.chain_name, ChainName::from_str(chain_name).unwrap());
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[test]
    fn config_load_fails_if_required_field_is_missing() {
        let ampd_url = "http://localhost:8080";

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("custom-config.toml");
        let content = format!(
            r#"
            ampd_url="{ampd_url}"
            "#
        );
        fs::write(&config_path, content).unwrap();

        let res = builder::<Config>().add_file_source(config_path).build();

        assert_err_contains!(res, Error, Error::Build);
    }

    #[test]
    fn config_loads_default_values_when_missing() {
        let chain_name = "some-chain";

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("custom-config.toml");
        let content = format!(
            r#"
            chain_name="{chain_name}"
            "#
        );
        fs::write(&config_path, content).unwrap();

        let config = builder::<Config>()
            .add_file_source(config_path)
            .build()
            .unwrap();

        assert_eq!(config.ampd_url, default_ampd_url());
        assert_eq!(
            config.event_handler,
            event::event_handler::Config::default()
        );
    }
}
