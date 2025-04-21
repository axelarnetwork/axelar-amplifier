fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .compile(&["proto/tofnd/multisig.proto"], &["proto/tofnd"])?;

    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .compile(
            &["proto/axelar/auxiliary/v1beta1/tx.proto"],
            &["proto", "proto/third_party"],
        )?;

    Ok(())
}
