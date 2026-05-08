//! Build script for `backseat`.
//!
//! At compile time this script locates the `libbackseat_payload.so` artifact
//! produced by the sibling `backseat-payload` crate and sets the
//! `BACKSEAT_PAYLOAD_PATH` environment variable so that `include_bytes!` can
//! embed it into the final binary.
//!
//! # Workflow
//!
//! 1. Build the payload first: `cargo build -p backseat-payload`
//! 2. Build the host crate: `cargo build -p backseat`
//!
//! The script panics with a helpful message if the payload artifact is missing.

use std::env;
use std::path::PathBuf;

fn main() {
    let _out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let profile = env::var("PROFILE").unwrap();
    let target = env::var("TARGET").unwrap();

    // Workspace target directory: <workspace_root>/target/<target>/<profile>
    let payload_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
        .join(&target)
        .join(&profile)
        .join("libbackseat_payload.so");

    let payload_path = if payload_path.exists() {
        payload_path
    } else {
        // Fallback for non-cross-compilation builds where Cargo does not
        // create a `<target>` subdirectory.
        let fallback = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
            .join(&profile)
            .join("libbackseat_payload.so");
        if fallback.exists() {
            fallback
        } else {
            panic!(
                "backseat-payload not found at {}. \
                 Build it first with: cargo build -p backseat-payload",
                payload_path.display()
            );
        }
    };

    println!(
        "cargo:rustc-env=BACKSEAT_PAYLOAD_PATH={}",
        payload_path.display()
    );
    println!("cargo:rerun-if-changed={}", payload_path.display());
}
