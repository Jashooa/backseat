use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let profile = env::var("PROFILE").unwrap();
    let target = env::var("TARGET").unwrap();

    let payload_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
        .join(&target)
        .join(&profile)
        .join("libbackseat_payload.so");

    if !payload_path.exists() {
        panic!(
            "backseat-payload not found at {}. Build ordering may be incorrect.",
            payload_path.display()
        );
    }

    println!("cargo:rustc-env=BACKSEAT_PAYLOAD_PATH={}", payload_path.display());
    println!("cargo:rerun-if-changed={}", payload_path.display());
}
