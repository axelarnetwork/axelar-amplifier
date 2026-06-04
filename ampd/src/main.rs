use std::fmt::Debug;
use std::fs::canonicalize;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ::config::{Config as cfg, Environment, File, FileFormat, FileSourceFile};
use ampd::commands::{
    bond_verifier, claim_stake, daemon, deregister_chain_support, register_chain_support,
    register_public_key, send_tokens, set_rewards_proxy, unbond_verifier, verifier_address,
    SubCommand,
};
use ampd::config::Config;
use ampd::Error;
use axelar_wasm_std::FnExt;
use clap::{Parser, ValueEnum};
use config::ConfigError;
use error_stack::{Report, ResultExt};
use report::LoggableError;
use tracing::{error, info, warn};
use tracing_core::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use valuable::Valuable;

const DEFAULT_CONFIG_PATHS: &[&str] = &["~/.ampd/config.toml", "config.toml"];

#[derive(Debug, Parser, Valuable)]
#[command(version)]
struct Args {
    /// Set the paths for config file lookup. Can be defined multiple times (configs get merged).
    /// If not provided, falls back to `~/.ampd/config.toml` and `./config.toml`.
    #[arg(short, long)]
    pub config: Vec<PathBuf>,

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

    let cfg = match init_config_or_exit(&args.config, &args.output) {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };

    let result = match args.cmd {
        Some(SubCommand::Daemon) | None => {
            info!(args = args.as_value(), "starting daemon");

            daemon::run(cfg).await.then(|result| {
                info!("shutting down");
                result
            })
        }
        Some(SubCommand::BondVerifier(args)) => bond_verifier::run(cfg, args).await,
        Some(SubCommand::RegisterChainSupport(args)) => {
            register_chain_support::run(cfg, args).await
        }
        Some(SubCommand::DeregisterChainSupport(args)) => {
            deregister_chain_support::run(cfg, args).await
        }
        Some(SubCommand::RegisterPublicKey(args)) => register_public_key::run(cfg, args).await,
        Some(SubCommand::VerifierAddress) => verifier_address::run(cfg.tofnd_config).await,
        Some(SubCommand::UnbondVerifier(args)) => unbond_verifier::run(cfg, args).await,
        Some(SubCommand::ClaimStake(args)) => claim_stake::run(cfg, args).await,
        Some(SubCommand::SendTokens(args)) => send_tokens::run(cfg, args).await,
        Some(SubCommand::SetRewardsProxy(args)) => set_rewards_proxy::run(cfg, args).await,
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

fn report_init_config_failure(report: &error_stack::Report<Error>, output: &Output) {
    error!(err = LoggableError::from(report).as_value(), "{report:#}");
    if matches!(output, Output::Text) {
        eprintln!("{report:?}");
    }
}

fn init_config_or_exit(config_paths: &[PathBuf], output: &Output) -> Result<Config, ExitCode> {
    init_config(config_paths).map_err(|report| {
        report_init_config_failure(&report, output);
        ExitCode::FAILURE
    })
}

fn set_up_logger(output: &Output) {
    let error_layer = ErrorLayer::default();
    let filter_layer = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    match output {
        Output::Json => {
            let fmt_layer = tracing_subscriber::fmt::layer().json().flatten_event(true);
            tracing_subscriber::registry()
                .with(error_layer)
                .with(filter_layer)
                .with(fmt_layer)
                .init();
        }
        Output::Text => {
            let fmt_layer = tracing_subscriber::fmt::layer().compact();
            tracing_subscriber::registry()
                .with(error_layer)
                .with(filter_layer)
                .with(fmt_layer)
                .init();
        }
    };
}

fn init_config(config_paths: &[PathBuf]) -> error_stack::Result<Config, Error> {
    init_config_with_defaults(config_paths, DEFAULT_CONFIG_PATHS)
}

fn init_config_with_defaults(
    config_paths: &[PathBuf],
    defaults: &[&str],
) -> error_stack::Result<Config, Error> {
    let files = find_config_files(config_paths, defaults)?;
    let env_keys: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| k.starts_with("AMPD_"))
        .collect();

    if files.is_empty() && env_keys.is_empty() {
        warn!("no config file or AMPD_* env vars found; using Config::default()");
    } else {
        info!(file_count = files.len(), env_vars = ?env_keys, "loading config");
    }

    Ok(parse_config(files)
        .change_context(Error::LoadConfig)
        .inspect_err(|report| error!(err = LoggableError::from(report).as_value(), "{report}"))
        .unwrap_or_default())
}

fn find_config_files(
    config: &[PathBuf],
    defaults: &[&str],
) -> error_stack::Result<Vec<File<FileSourceFile, FileFormat>>, Error> {
    let (paths, user_supplied) = if config.is_empty() {
        (
            defaults.iter().map(PathBuf::from).collect::<Vec<_>>(),
            false,
        )
    } else {
        (config.to_vec(), true)
    };

    let mut files = Vec::new();
    for path in paths {
        let expanded = expand_home_dir(&path);
        match canonicalize(&expanded) {
            Ok(canonical) => {
                info!("found config file {}", canonical.to_string_lossy());
                files.push(File::from(canonical));
            }
            Err(err) if !user_supplied && err.kind() == io::ErrorKind::NotFound => {
                // default candidate does not exist on this install; skip silently
            }
            Err(err) if !user_supplied => {
                warn!(path = %expanded.to_string_lossy(), err = %err, "skipping default config file");
            }
            Err(err) => {
                return Err(Report::from(err)
                    .change_context(Error::LoadConfig)
                    .attach_printable(format!(
                        "failed to resolve config path: {}",
                        expanded.display()
                    )));
            }
        }
    }

    if files.is_empty() {
        info!("found no config files to load");
    }

    Ok(files)
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

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;
    use tracing_test::traced_test;

    use super::*;

    fn make_file(dir: &TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, b"").expect("write temp file");
        path
    }

    #[traced_test]
    #[test]
    fn find_config_files_resolves_user_supplied_path() {
        let dir = TempDir::new().unwrap();
        let path = make_file(&dir, "ampd.toml");

        let files = find_config_files(&[path], &[]).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn find_config_files_collects_all_user_supplied_paths() {
        let dir = TempDir::new().unwrap();
        let a = make_file(&dir, "a.toml");
        let b = make_file(&dir, "b.toml");

        let files = find_config_files(&[a, b], &[]).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn find_config_files_errors_on_missing_user_supplied_path() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope.toml");

        let err = find_config_files(std::slice::from_ref(&missing), &[]).unwrap_err();
        let formatted = format!("{err:?}");
        assert!(
            formatted.contains(&missing.display().to_string()),
            "expected error to mention path, got: {formatted}",
        );
    }

    #[test]
    fn find_config_files_errors_when_any_user_supplied_path_is_missing() {
        let dir = TempDir::new().unwrap();
        let good = make_file(&dir, "good.toml");
        let missing = dir.path().join("missing.toml");

        assert!(find_config_files(&[good, missing], &[]).is_err());
    }

    #[test]
    fn find_config_files_returns_empty_when_no_user_paths_and_no_defaults_exist() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("not-there.toml");
        let missing_str = missing.to_str().unwrap().to_string();

        let files = find_config_files(&[], &[missing_str.as_str()]).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn find_config_files_picks_up_existing_default() {
        let dir = TempDir::new().unwrap();
        let existing = make_file(&dir, "default.toml");
        let existing_str = existing.to_str().unwrap().to_string();

        let files = find_config_files(&[], &[existing_str.as_str()]).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn find_config_files_skips_missing_defaults_silently() {
        let dir = TempDir::new().unwrap();
        let existing = make_file(&dir, "exists.toml");
        let missing = dir.path().join("absent.toml");
        let existing_str = existing.to_str().unwrap().to_string();
        let missing_str = missing.to_str().unwrap().to_string();

        let files = find_config_files(&[], &[missing_str.as_str(), existing_str.as_str()]).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn find_config_files_errors_on_unreadable_user_supplied_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let restricted = dir.path().join("locked");
        fs::create_dir(&restricted).unwrap();
        let path = restricted.join("config.toml");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000)).unwrap();

        // root bypasses chmod, which would invalidate the test premise; detect by
        // probing the FS rather than depending on libc
        if canonicalize(&path).is_ok() {
            fs::set_permissions(&restricted, fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }

        let result = find_config_files(&[path], &[]);

        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(result.is_err(), "expected error, got {result:?}");
    }

    #[test]
    fn expand_home_dir_leaves_non_tilde_paths_untouched() {
        let path = PathBuf::from("/etc/ampd/config.toml");
        assert_eq!(expand_home_dir(&path), path);
    }

    #[test]
    fn expand_home_dir_replaces_leading_tilde() {
        let Some(home) = dirs::home_dir() else {
            return;
        };

        assert_eq!(
            expand_home_dir(PathBuf::from("~/.ampd/config.toml")),
            home.join(".ampd/config.toml"),
        );
    }

    #[test]
    fn expand_home_dir_does_not_match_tilde_inside_path_segment() {
        // `~foo` is not a tilde-home path; it should pass through unchanged
        let path = PathBuf::from("~foo/bar");
        assert_eq!(expand_home_dir(&path), path);
    }

    #[cfg(unix)]
    #[traced_test]
    #[test]
    fn find_config_files_skips_unreadable_default_with_warning() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let restricted = dir.path().join("locked");
        fs::create_dir(&restricted).unwrap();
        let default_path = restricted.join("default.toml");
        fs::write(&default_path, b"").unwrap();
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000)).unwrap();

        if canonicalize(&default_path).is_ok() {
            fs::set_permissions(&restricted, fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }

        let default_str = default_path.to_string_lossy().into_owned();
        let result = find_config_files(&[], &[default_str.as_str()]);

        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o755)).unwrap();

        let files = result.expect("default-path errors should not propagate");
        assert!(files.is_empty());
    }

    fn ampd_env_keys() -> Vec<String> {
        std::env::vars_os()
            .filter_map(|(k, _)| k.into_string().ok())
            .filter(|k| k.starts_with("AMPD_"))
            .collect()
    }

    #[traced_test]
    #[test]
    fn init_config_succeeds_with_user_supplied_file() {
        let dir = TempDir::new().unwrap();
        let path = make_file(&dir, "ampd.toml");

        assert!(init_config(&[path]).is_ok());
    }

    #[test]
    fn init_config_propagates_user_path_resolution_errors() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope.toml");

        assert!(init_config(&[missing]).is_err());
    }

    #[traced_test]
    #[test]
    fn init_config_falls_back_to_default_when_no_sources_present() {
        let keys = ampd_env_keys();

        temp_env::with_vars_unset(keys.as_slice(), || {
            // empty user paths + empty defaults + no AMPD_* env vars exercises
            // the warn-and-fall-back branch deterministically
            let cfg = init_config_with_defaults(&[], &[]).expect("should not error");
            assert_eq!(cfg, Config::default());
        });
    }

    #[traced_test]
    #[test]
    fn report_init_config_failure_runs_for_text_and_json_output() {
        let report = error_stack::Report::new(Error::LoadConfig);

        // both branches should run without panicking; Text additionally writes to stderr
        report_init_config_failure(&report, &Output::Text);
        report_init_config_failure(&report, &Output::Json);
    }

    #[traced_test]
    #[test]
    fn init_config_or_exit_returns_failure_on_invalid_path() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope.toml");

        assert!(init_config_or_exit(&[missing], &Output::Json).is_err());
    }

    #[traced_test]
    #[test]
    fn init_config_or_exit_returns_config_on_valid_path() {
        let dir = TempDir::new().unwrap();
        let path = make_file(&dir, "ampd.toml");

        assert!(init_config_or_exit(&[path], &Output::Text).is_ok());
    }
}
