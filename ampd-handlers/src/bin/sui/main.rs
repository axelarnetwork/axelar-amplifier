mod error;
mod handler;

use std::collections::HashMap;
use std::time::Duration;

use ampd::asyncutil::task::{CancellableTask, TaskGroup};
use ampd::url::Url;
use ampd_handlers::sui::rpc_client::Client;
use ampd_handlers::tracing::init_tracing;
use ampd_handlers::{multisig, Args};
use ampd_sdk::config;
use ampd_sdk::runtime::HandlerRuntime;
use axelar_wasm_std::chain::ChainName;
use clap::Parser;
#[cfg(debug_assertions)]
use dotenv_flow::dotenv_flow;
use error_stack::{Result, ResultExt};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::Level;

use crate::error::Error;
use crate::handler::Handler;

// No `Debug` or `Serialize`: the headers carry provider credentials.
#[derive(Clone, Deserialize)]
struct SuiHandlerConfig {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    rpc_url: Url,
    #[serde(with = "humantime_serde")]
    #[serde(default = "default_rpc_timeout")]
    rpc_timeout: Duration,
    /// Headers sent with every RPC request, e.g. a provider's authentication token.
    /// A table in the config file, or `name=value[,name=value...]` in the
    /// `AMPD_SUI_HANDLER_RPC_HEADERS` environment variable.
    #[serde(default, deserialize_with = "deserialize_headers")]
    rpc_headers: HashMap<String, String>,
}

fn default_rpc_timeout() -> Duration {
    Duration::from_secs(3)
}

/// Accepts the headers either as a map (config file) or as a single
/// `name=value[,name=value...]` string (environment variable, which cannot express a map).
/// Names and values are trimmed; values may not contain commas.
///
/// Errors identify a malformed pair by its position only: the pairs carry credentials
/// and the error ends up in startup logs.
fn deserialize_headers<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Headers {
        Map(HashMap<String, String>),
        Pairs(String),
    }

    match Headers::deserialize(deserializer)? {
        Headers::Map(headers) => Ok(headers),
        Headers::Pairs(pairs) => pairs
            .split(',')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
            .enumerate()
            .map(|(index, pair)| {
                pair.split_once('=')
                    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
                    .filter(|(name, _)| !name.is_empty())
                    .ok_or_else(|| {
                        serde::de::Error::custom(format!(
                            "rpc header {} is not of the form `name=value`",
                            index.saturating_add(1)
                        ))
                    })
            })
            .collect(),
    }
}

fn build_handler(
    runtime: &HandlerRuntime,
    chain_name: ChainName,
    config: SuiHandlerConfig,
) -> Result<Handler<Client>, Error> {
    let rpc_client = Client::new(
        &config.rpc_url,
        config.rpc_timeout,
        config.rpc_headers,
        runtime.monitoring_client.clone(),
        chain_name.clone(),
    )
    .change_context(Error::HandlerStart)?;

    let handler = Handler::builder()
        .verifier(runtime.verifier.clone())
        .voting_verifier_contract(runtime.contracts.voting_verifier.clone())
        .chain(chain_name)
        .rpc_client(rpc_client)
        .monitoring_client(runtime.monitoring_client.clone())
        .build();

    Ok(handler)
}

fn voting_handler_task(
    runtime: HandlerRuntime,
    base_config: config::Config,
    handler_config: SuiHandlerConfig,
) -> CancellableTask<Result<(), Error>> {
    CancellableTask::create(move |token| async move {
        let handler = build_handler(&runtime, base_config.chain_name.clone(), handler_config)?;

        runtime
            .run_handler(handler, base_config, token)
            .await
            .change_context(Error::HandlerTask)
    })
}

fn multisig_handler_task(
    runtime: HandlerRuntime,
    base_config: config::Config,
) -> CancellableTask<Result<(), Error>> {
    CancellableTask::create(move |token| async move {
        let handler = multisig::Handler::new(&runtime, base_config.chain_name.clone());

        runtime
            .run_handler(handler, base_config, token)
            .await
            .change_context(Error::HandlerTask)
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Load environment variables from .env files in debug builds
    #[cfg(debug_assertions)]
    dotenv_flow().ok();

    let args: Args = Args::parse();
    init_tracing(Level::INFO);

    let base_config = config::Config::from_default_sources(args.config_dir.clone())
        .change_context(Error::HandlerStart)?;
    let handler_config = config::builder::<SuiHandlerConfig>()
        .add_file_source(args.config_dir.join("sui-handler-config.toml"))
        .add_env_source("AMPD_SUI_HANDLER")
        .build()
        .change_context(Error::HandlerStart)?;

    let token = CancellationToken::new();

    let runtime = HandlerRuntime::start(&base_config, token.clone())
        .await
        .change_context(Error::HandlerStart)?;

    let mut task_group = TaskGroup::new("sui-handlers");

    task_group = task_group.add_task(
        "voting-handler",
        voting_handler_task(runtime.clone(), base_config.clone(), handler_config.clone()),
    );
    task_group = task_group.add_task(
        "multisig-handler",
        multisig_handler_task(runtime, base_config),
    );

    task_group
        .run(token)
        .await
        .change_context(Error::TaskGroup)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde::Deserialize;
    use serde_json::json;

    use super::deserialize_headers;

    #[derive(Deserialize)]
    struct Config {
        #[serde(default, deserialize_with = "deserialize_headers")]
        rpc_headers: HashMap<String, String>,
    }

    fn headers(value: serde_json::Value) -> serde_json::Result<HashMap<String, String>> {
        serde_json::from_value::<Config>(value).map(|config| config.rpc_headers)
    }

    #[test]
    fn should_default_to_no_headers() {
        assert!(headers(json!({})).unwrap().is_empty());
    }

    #[test]
    fn should_accept_headers_as_map() {
        let parsed = headers(json!({ "rpc_headers": { "x-token": "secret" } })).unwrap();
        assert_eq!(
            parsed,
            HashMap::from([("x-token".to_string(), "secret".to_string())])
        );
    }

    #[test]
    fn should_accept_headers_as_pairs() {
        let parsed = headers(json!({
            "rpc_headers": " x-token = secret , authorization=Bearer abc=def,"
        }))
        .unwrap();
        assert_eq!(
            parsed,
            HashMap::from([
                ("x-token".to_string(), "secret".to_string()),
                ("authorization".to_string(), "Bearer abc=def".to_string()),
            ])
        );
    }

    #[test]
    fn should_accept_empty_pairs() {
        assert!(headers(json!({ "rpc_headers": "" })).unwrap().is_empty());
    }

    #[test]
    fn should_reject_malformed_pairs() {
        assert!(headers(json!({ "rpc_headers": "x-token" })).is_err());
        assert!(headers(json!({ "rpc_headers": "=secret" })).is_err());
        assert!(headers(json!({ "rpc_headers": "x-token=a,oops" })).is_err());
    }

    #[test]
    fn should_not_echo_malformed_pairs() {
        let err = headers(json!({ "rpc_headers": "x-token=ok, Bearer secret-credential" }))
            .unwrap_err()
            .to_string();

        assert!(err.contains("rpc header 2"), "{err}");
        assert!(!err.contains("secret-credential"), "{err}");
        assert!(!err.contains("Bearer"), "{err}");
    }
}
