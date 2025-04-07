fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile(&["ampd-proto/ampd/v1/ampd.proto"], &["ampd-proto/ampd/v1"])?;

    Ok(())
}
