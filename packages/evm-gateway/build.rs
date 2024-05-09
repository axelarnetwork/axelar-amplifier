use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use reqwest::blocking::Client;
use zip::ZipArchive;

const SOLIDITY_RELEASES_URL: &str =
    "https://github.com/axelarnetwork/axelar-gmp-sdk-solidity/releases/download";

const OUTPUT_DIR: &str = "interfaces";

const INTERFACE_FILES: [&str; 2] = ["IAxelarAmplifierGateway.sol", "IBaseWeightedMultisig.sol"];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(feature = "run-script") {
        return Ok(());
    }

    let version_tag = env::var("SOLIDITY_GATEWAY_VERSION")
        .expect("Environment variable SOLIDITY_GATEWAY_VERSION is not set");

    let zipfile_name = format!("Bytecode-{}.zip", version_tag);
    let url = format!(
        "{}/{}/{}",
        SOLIDITY_RELEASES_URL, version_tag, &zipfile_name
    );
    let zipfile_path = PathBuf::from(&zipfile_name);

    download_and_extract(&url, &zipfile_path)?;

    fs::remove_file(zipfile_path)?;

    Ok(())
}

fn download_and_extract(url: &str, zip_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let mut response = client.get(url).send()?;
    if !response.status().is_success() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to download {}", url),
        )));
    }

    let mut zipfile = File::create(zip_path)?;
    io::copy(&mut response, &mut zipfile)?;

    extract_files(zip_path)?;
    Ok(())
}

fn extract_files(zip_path: &Path) -> io::Result<()> {
    let zipfile = File::open(zip_path)?;
    let mut archive = ZipArchive::new(zipfile)?;

    for interface_file in INTERFACE_FILES.iter() {
        let path = format!("flattened/interfaces/{}", interface_file);

        let mut file = match archive.by_name(&path) {
            Ok(file) => file,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("File not found in archive: {}", interface_file),
                ))
            }
        };

        let output_path = Path::new(OUTPUT_DIR).join(interface_file);
        let mut output_file = File::create(&output_path)?;

        io::copy(&mut file, &mut output_file)?;
    }

    Ok(())
}
