use std::fmt::Debug;
use std::fs::canonicalize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ::config::{Config as cfg, Environment, File, FileFormat, FileSourceFile};
use clap::{Parser, ValueEnum};
use config::ConfigError;
use error_stack::{Report, ResultExt};
use thiserror::Error;
use tracing::{error, info};
use valuable::Valuable;

use ampd::config::Config;
use ampd::{run, state};
use axelar_wasm_std::utils::InspectorResult;
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
    #[arg(short, long, value_enum, default_value_t = Output::Json)]
    pub output: Output,
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

    info!(args = args.as_value(), "starting daemon");
    let result = run_daemon(&args)
        .await
        .tap_err(|report| error!(err = LoggableError::from(report).as_value(), "{report:#}"));
    info!("shutting down");

    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(report) => {
            // print detailed error report as the last output if in text mode
            if matches!(args.output, Output::Text) {
                eprintln!("{report:?}");
            }

            ExitCode::FAILURE
        }
    }
}

async fn run_daemon(args: &Args) -> Result<(), Report<Error>> {
    let cfg = init_config(&args.config);
    let state_path = expand_home_dir(&args.state);

    let state = state::load(&state_path).change_context(Error::Fatal)?;
    let (state, execution_result) = run(cfg, state).await;
    let state_flush_result = state::flush(&state, state_path).change_context(Error::Fatal);

    let execution_result = execution_result.change_context(Error::Fatal);
    match (execution_result, state_flush_result) {
        // both execution and persisting state failed: return the merged error
        (Err(mut report), Err(state_err)) => {
            report.extend_one(state_err);
            Err(report)
        }

        // any single path failed: report the error
        (Err(report), Ok(())) | (Ok(()), Err(report)) => Err(report),

        // no errors in either execution or persisting state
        (Ok(()), Ok(())) => Ok(()),
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
    let Ok(home_subfolder) = path.strip_prefix("~") else{
        return path.to_path_buf()
    };

    dirs::home_dir().map_or(path.to_path_buf(), |home| home.join(home_subfolder))
}

#[derive(Error, Debug)]
enum Error {
    #[error("failed to load config")]
    LoadConfig,
    #[error("fatal failure")]
    Fatal,
}
