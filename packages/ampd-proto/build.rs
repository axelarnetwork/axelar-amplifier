fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .extern_path(".google.protobuf.Any", "::cosmrs::Any")
        .compile_protos(
            &["proto-files/ampd/v1/ampd.proto"],
            &["proto-files/ampd/v1"],
        )?;

    Ok(())
}
