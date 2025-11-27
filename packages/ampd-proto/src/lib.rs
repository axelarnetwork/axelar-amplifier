pub use proto::*;

mod proto {
    tonic::include_proto!("ampd.v1");
}

mod utils;
