use std::env;
use std::fs;
use std::path::Path;

// This is a build script that copies the gateway's msg.rs file into the current crate.
// This is needed to avoid a circular dependency, where the gateway includes the router (for routing messages)
// and the router includes the gateway (for delivering routed messages)
// This script runs prior to compilation of any other files
// Reference: https://doc.rust-lang.org/cargo/reference/build-script-examples.html
fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("gateway_msg.rs"); // write the output to a build file called gateway_msg.rs
    let contents =
        fs::read_to_string("../gateway/src/msg.rs").expect("Failed to read gateway's msg.rs file");

    let transformed = contents
        .lines()
        .map(|l| {
            if l.contains("connection_router") {
                // need to adjust use statements to use crate::* instead of connection_router::*
                l.replace("connection_router", "crate")
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<String>>()
        .join("\n");

    fs::write(dest_path, transformed).expect("Failed to write build file");

    // rerun this script if the file changes, or if the gateway's msg.rs file changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../gateway/src/msg.rs");
}
