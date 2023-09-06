use std::fmt::Debug;
use std::fs::canonicalize;
use std::path::PathBuf;
use std::process::ExitCode;

use ::config::{Config as cfg, Environment, File, FileFormat, FileSourceFile};
use clap::{command, Parser, Subcommand, ValueEnum};
use config::ConfigError;
use error_stack::Report;
use tracing::{error, info};

use ampd::config::Config;
use ampd::report::LoggableError;
use ampd::run;
use valuable::Valuable;

#[derive(Debug, Parser)]
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

    #[clap(subcommand)]
    pub cmd: Option<SubCommand>,
}

#[derive(Debug, Clone, Parser, ValueEnum)]
enum Output {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum SubCommand {
    /// Run the ampd daemon process (default)
    Daemon,
    /// Register this node as a worker
    RegisterWorker,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Args = Args::parse();
    set_up_logger(&args.output);

    match args.cmd {
        Some(SubCommand::RegisterWorker) => register_worker(args),
        Some(SubCommand::Daemon) | None => run_daemon(args).await,
    }
}

async fn run_daemon(args: Args) -> ExitCode {
    info!("starting daemon");

    let cfg = init_config(&args);
    let code = match run(cfg, args.state).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(report) => {
            let err = LoggableError::from(&report);
            error!(err = err.as_value(), "{report}");
            if matches!(args.output, Output::Text) {
                eprintln!("{report:?}");
            }
            ExitCode::FAILURE
        }
    };
    info!("shutting down");
    code
}

fn register_worker(args: Args) -> ExitCode {
    println!("registering worker");
    println!("args: {:?}", args);
    ExitCode::SUCCESS
}

fn init_config(args: &Args) -> Config {
    let files = find_config_files(&args.config);
    info!("found {} config files to load", files.len());

    match parse_config(files).map_err(Report::from) {
        Ok(cfg) => cfg,
        Err(report) => {
            let err = LoggableError::from(&report);
            error!(
                err = err.as_value(),
                "failed to load config, falling back to default"
            );
            Config::default()
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

fn find_config_files(config: &[PathBuf]) -> Vec<File<FileSourceFile, FileFormat>> {
    config
        .iter()
        .map(canonicalize)
        .filter_map(Result::ok)
        .map(File::from)
        .collect()
}

fn parse_config(files: Vec<File<FileSourceFile, FileFormat>>) -> Result<Config, ConfigError> {
    cfg::builder()
        .add_source(files)
        .add_source(Environment::with_prefix(clap::crate_name!()))
        .build()?
        .try_deserialize::<Config>()
}
