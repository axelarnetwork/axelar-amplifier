use std::path::{Path, PathBuf};
use std::{env, fs};

use clap::{arg, Parser};
use error_stack::{Result, ResultExt};
use thiserror::Error;
use toml::Table;

#[derive(Error, Debug)]
enum Error {
    #[error("failed to parse contract's Cargo.toml")]
    Cargo,
    #[error("failed to read template file")]
    Template,
    #[error("failed to reset contract's 'migrations' module")]
    MigrationMod,
}

#[derive(Parser, Debug)]
struct Args {
    /// Name of contract's crate, e.g. "axelarnet-gateway"
    #[arg(short, long)]
    pub contract: String,
}

const CONTRACTS_RELATIVE_PATH: &str = "../../contracts/";
const TEMPLATE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/template.rs");

fn next_migrate_version_req(cargo_toml_path: PathBuf) -> Result<String, Error> {
    let content = fs::read_to_string(cargo_toml_path).change_context(Error::Cargo)?;
    let parsed_toml = content.parse::<Table>().change_context(Error::Cargo)?;

    let version = parsed_toml
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(|version| version.as_str())
        .ok_or(Error::Cargo)?;

    Ok(version.split(".").take(2).collect::<Vec<_>>().join("."))
}

fn read_template(contract_root_dir: &Path) -> Result<String, Error> {
    let from_version = next_migrate_version_req(contract_root_dir.join("Cargo.toml"))?;

    let template = fs::read_to_string(TEMPLATE_PATH)
        .change_context(Error::Template)?
        .replace(
            r#"#[migrate_from_version("0.0")]"#,
            &format!(r#"#[migrate_from_version("{}")]"#, from_version),
        );

    Ok(template)
}

fn reset_migration_mod(contract_root_dir: &Path, content: &str) -> Result<(), Error> {
    let migrations_mod_dir = contract_root_dir.join("src/contract/migrations");

    fs::remove_dir_all(&migrations_mod_dir)
        .and_then(|_| fs::create_dir(&migrations_mod_dir))
        .and_then(|_| fs::write(migrations_mod_dir.join("mod.rs"), content))
        .change_context(Error::MigrationMod)
}

fn main() -> Result<(), Error> {
    let args = Args::parse();

    let contract_root_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(CONTRACTS_RELATIVE_PATH)
        .join(&args.contract);

    read_template(&contract_root_dir)
        .and_then(|template| reset_migration_mod(&contract_root_dir, &template))?;

    println!(
        "Migration code removed successfully from contract `{}`",
        args.contract
    );

    Ok(())
}

// tests that `template.rs` compiles correctly
#[cfg(test)]
mod template;
