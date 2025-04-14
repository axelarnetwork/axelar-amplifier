fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["proto-files/ampd/v1/ampd.proto"],
            &["proto-files/ampd/v1"],
        )?;

    Ok(())
}
