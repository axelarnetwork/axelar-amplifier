pub use proto::*;

// Generated Tonic methods return tonic::Status; its representation is upstream-owned.
#[allow(clippy::result_large_err)]
mod proto {
    tonic::include_proto!("ampd.v1");
}

mod utils;
