fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().build_server(false).compile(
        &["internal-proto/tofnd/multisig.proto"],
        &["internal-proto/tofnd"],
    )?;

    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .compile(
            &["internal-proto/axelar/auxiliary/v1beta1/tx.proto"],
            &["internal-proto", "internal-proto/third_party"],
        )?;

    Ok(())
}
