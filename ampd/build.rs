fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .compile(
            &["proto/tofnd/multisig.proto", "proto/flow/access.proto"],
            &["proto/tofnd", "proto/flow"]
        )?;
    Ok(())
}