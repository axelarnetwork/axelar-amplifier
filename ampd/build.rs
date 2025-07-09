fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["proto/tofnd/multisig.proto"], &["proto/tofnd"])?;

    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .extern_path(".google.protobuf.Any", "::cosmrs::Any")
        .compile_protos(
            &["proto/axelar/auxiliary/v1beta1/tx.proto"],
            &["proto", "proto/third_party"],
        )?;

    Ok(())
}
