use clap::{arg, Parser};
use error_stack::{Result, ResultExt};
use std::{env, fs, path::Path};
use thiserror::Error;

#[derive(Error, Debug)]
#[error("failed to remove migration code")]
struct Error;

#[derive(Parser, Debug)]
struct Args {
    /// Name of contract's crate, e.g. "axelarnet-gateway"
    #[arg(short, long)]
    pub contract: String,
}

const CONTRACTS_RELATIVE_PATH: &str = "../../contracts/";
const TEMPLATE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/template.rs");

fn main() -> Result<(), Error> {
    let args = Args::parse();
    println!("Removing migration code from {} contract", args.contract);

    let migrations_mod_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(CONTRACTS_RELATIVE_PATH)
        .join(&args.contract)
        .join("src/contract/migrations");

    fs::remove_dir_all(&migrations_mod_dir).change_context(Error)?;
    fs::create_dir(&migrations_mod_dir).change_context(Error)?;

    let template = fs::read_to_string(TEMPLATE_PATH).change_context(Error)?;
    fs::write(&migrations_mod_dir.join("mod.rs"), template).change_context(Error)?;

    Ok(())
}
