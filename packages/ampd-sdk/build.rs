fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .type_attribute(".", "#[derive(Default)]")
        .compile(&["ampd-proto/ampd/v1/ampd.proto"], &["ampd-proto"])?;

    Ok(())
}
