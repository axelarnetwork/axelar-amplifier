use prost::Name;

#[allow(
    dead_code,
    reason = "tonic generates the full proto message set; ampd uses only a subset"
)]
pub mod axelar {
    pub mod auxiliary {
        pub mod v1beta1 {
            tonic::include_proto!("axelar.auxiliary.v1beta1");
        }
    }
}

#[allow(
    dead_code,
    reason = "tonic generates the full proto message set; ampd uses only a subset"
)]
mod cosmos {
    pub mod base {
        pub mod abci {
            pub mod v1beta1 {
                tonic::include_proto!("cosmos.base.abci.v1beta1");
            }
        }
    }
}

#[allow(
    dead_code,
    reason = "tonic generates the full proto message set; ampd uses only a subset"
)]
mod tendermint {
    #[allow(clippy::large_enum_variant)]
    pub mod abci {
        tonic::include_proto!("tendermint.abci");
    }

    pub mod crypto {
        tonic::include_proto!("tendermint.crypto");
    }

    pub mod types {
        tonic::include_proto!("tendermint.types");
    }

    pub mod version {
        tonic::include_proto!("tendermint.version");
    }
}

impl Name for axelar::auxiliary::v1beta1::BatchRequest {
    const NAME: &'static str = "BatchRequest";
    const PACKAGE: &'static str = "axelar.auxiliary.v1beta1";
}
