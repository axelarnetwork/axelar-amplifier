use std::fmt::Debug;
use std::fs::canonicalize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ::config::{Config as cfg, Environment, File, FileFormat, FileSourceFile};
use clap::{arg, command, Parser, ValueEnum};
use config::ConfigError;
use error_stack::{Report, ResultExt};
use tracing::{error, info};
use valuable::Valuable;

use ampd::commands::{
    bond_worker, daemon, deregister_chain_support, register_chain_support, register_public_key,
    worker_address, SubCommand,
};
use ampd::config::Config;
use ampd::Error;
use axelar_wasm_std::utils::InspectorResult;
use axelar_wasm_std::FnExt;
use report::LoggableError;

#[derive(Debug, Parser, Valuable)]
#[command(version)]
struct Args {
    /// Set the paths for config file lookup. Can be defined multiple times (configs get merged)
    #[arg(short, long, default_values_os_t = vec![std::path::PathBuf::from("~/.ampd/config.toml"), std::path::PathBuf::from("config.toml")])]
    pub config: Vec<PathBuf>,

    /// Set the paths for state file lookup
    #[arg(short, long, default_value_os_t = std::path::PathBuf::from("~/.ampd/state.json"))]
    pub state: PathBuf,

    /// Set the output style of the logs
    #[arg(short, long, value_enum, default_value_t = Output::Text)]
    pub output: Output,

    #[clap(subcommand)]
    pub cmd: Option<SubCommand>,
}

#[derive(Debug, Clone, Parser, ValueEnum, Valuable)]
enum Output {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Args = Args::parse();
    set_up_logger(&args.output);

    let cfg = init_config(&args.config);
    let state_path = expand_home_dir(&args.state);

    let result = match args.cmd {
        Some(SubCommand::Daemon) | None => {
            info!(args = args.as_value(), "starting daemon");

            daemon::run(cfg, &state_path).await.then(|result| {
                info!("shutting down");
                result
            })
        }
        Some(SubCommand::BondWorker(args)) => bond_worker::run(cfg, &state_path, args).await,
        Some(SubCommand::RegisterChainSupport(args)) => {
            register_chain_support::run(cfg, &state_path, args).await
        }
        Some(SubCommand::DeregisterChainSupport(args)) => {
            deregister_chain_support::run(cfg, &state_path, args).await
        }
        Some(SubCommand::RegisterPublicKey) => register_public_key::run(cfg, &state_path).await,
        Some(SubCommand::WorkerAddress) => worker_address::run(cfg.tofnd_config, &state_path).await,
    };

    match result {
        Ok(response) => {
            if let Some(resp) = response {
                info!("{}", resp);
            }
            ExitCode::SUCCESS
        }
        Err(report) => {
            error!(err = LoggableError::from(&report).as_value(), "{report:#}");

            // print detailed error report as the last output if in text mode
            if matches!(args.output, Output::Text) {
                eprintln!("{report:?}");
            }

            ExitCode::FAILURE
        }
    }
}

fn set_up_logger(output: &Output) {
    match output {
        Output::Json => {
            tracing_subscriber::fmt().json().flatten_event(true).init();
        }
        Output::Text => {
            tracing_subscriber::fmt().compact().init();
        }
    };
}

fn init_config(config_paths: &[PathBuf]) -> Config {
    let files = find_config_files(config_paths);

    parse_config(files)
        .change_context(Error::LoadConfig)
        .tap_err(|report| error!(err = LoggableError::from(report).as_value(), "{report}"))
        .unwrap_or(Config::default())
}

fn find_config_files(config: &[PathBuf]) -> Vec<File<FileSourceFile, FileFormat>> {
    let files = config
        .iter()
        .map(expand_home_dir)
        .map(canonicalize)
        .filter_map(Result::ok)
        .inspect(|path| info!("found config file {}", path.to_string_lossy()))
        .map(File::from)
        .collect::<Vec<_>>();

    if files.is_empty() {
        info!("found no config files to load");
    }

    files
}

fn parse_config(
    files: Vec<File<FileSourceFile, FileFormat>>,
) -> error_stack::Result<Config, ConfigError> {
    cfg::builder()
        .add_source(files)
        .add_source(Environment::with_prefix(clap::crate_name!()))
        .build()?
        .try_deserialize::<Config>()
        .map_err(Report::from)
}

fn expand_home_dir(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let Ok(home_subfolder) = path.strip_prefix("~") else {
        return path.to_path_buf();
    };

    dirs::home_dir().map_or(path.to_path_buf(), |home| home.join(home_subfolder))
}
