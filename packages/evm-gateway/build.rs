use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use reqwest::blocking::Client;
use zip::ZipArchive;

const ABI_FILES: [&str; 2] = ["IAxelarAmplifierGateway.json", "IBaseWeightedMultisig.json"];
const OUTPUT_DIR_BASE: &str = "src/abi"; // Base output directory

const VERSION: &str = env!(
    "SOLIDITY_GATEWAY_VERSION",
    "environment variable SOLIDITY_GATEWAY_VERSION is not set"
);
const URL: &str = env!(
    "SOLIDITY_RELEASES_URL",
    "environment variable SOLIDITY_RELEASES_URL is not set"
);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Append version to output directory
    let output_dir = format!("{}/{}/", OUTPUT_DIR_BASE, VERSION);

    // Skip if files already exist
    if files_exist(&output_dir, &ABI_FILES) {
        return Ok(());
    }

    let zipfile_name = format!("Bytecode-{}.zip", VERSION);
    let url = format!("{}/{}/{}", URL, VERSION, &zipfile_name);
    let zipfile_path = PathBuf::from(&zipfile_name);

    let mut zip_archive = download(&url, &zipfile_path)?;

    extract(&mut zip_archive, &output_dir)?;

    fs::remove_file(zipfile_path)?;

    Ok(())
}

fn files_exist(output_dir: &str, files: &[&str]) -> bool {
    let output_path = Path::new(output_dir);
    files.iter().all(|file| output_path.join(file).exists())
}

fn download(url: &str, zip_path: &Path) -> Result<ZipArchive<File>, Box<dyn std::error::Error>> {
    let client = Client::new();
    let mut response = client.get(url).send()?;
    if !response.status().is_success() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            format!("failed to download {}", url),
        )));
    }

    let mut zipfile = File::create(zip_path)?;
    io::copy(&mut response, &mut zipfile)?;

    let zipfile = File::open(zip_path)?;
    Ok(ZipArchive::new(zipfile)?)
}

fn extract(archive: &mut ZipArchive<File>, output_dir: &str) -> io::Result<()> {
    let abi_output = Path::new(output_dir);

    fs::create_dir_all(abi_output)?;

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
                format!("file not found in archive: {}", file_path),
            )
        })?;

        let mut output_file = File::create(output_path)?;
        io::copy(&mut file, &mut output_file)?;
    }

    Ok(())
}
