use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use reqwest::blocking::Client;
use zip::ZipArchive;

const SOLIDITY_RELEASES_URL: &str =
    "https://github.com/axelarnetwork/axelar-gmp-sdk-solidity/releases/download";

const ABI_FILES: [&str; 2] = ["IAxelarAmplifierGateway.json", "IBaseWeightedMultisig.json"];

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

    let mut zip_archive = download(&url, &zipfile_path)?;

    extract(&mut zip_archive)?;

    fs::remove_file(zipfile_path)?;

    Ok(())
}

fn download(url: &str, zip_path: &Path) -> Result<ZipArchive<File>, Box<dyn std::error::Error>> {
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

    let zipfile = File::open(zip_path)?;
    Ok(ZipArchive::new(zipfile)?)
}

fn extract(archive: &mut ZipArchive<File>) -> io::Result<()> {
    let abi_output = Path::new("src/abi");

    for abi in ABI_FILES.iter() {
        let file_path = format!(
            "contracts/interfaces/{}.sol/{}",
            abi.trim_end_matches(".json"),
            abi
        );
        let output_path = abi_output.join(abi);

        let mut file = archive.by_name(&file_path).map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found in archive: {}", file_path),
            )
        })?;

        let mut output_file = File::create(output_path)?;
        io::copy(&mut file, &mut output_file)?;
    }

    Ok(())
}
