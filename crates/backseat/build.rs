use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let profile = env::var("PROFILE").unwrap();
    let target = env::var("TARGET").unwrap();

    // Re-run whenever the vendored payload source changes.
    let vendored_src = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("src")
        .join("payload")
        .join("lib.rs");
    println!("cargo:rerun-if-changed={}", vendored_src.display());
    println!("cargo:rerun-if-changed=build.rs");

    let vendored_project = out_dir.join("payload-project");
    let vendored_src_dir = vendored_project.join("src");
    std::fs::create_dir_all(&vendored_src_dir).expect("failed to create payload src dir");

    // Minimal Cargo.toml — the payload has few deps and they're stable.
    let cargo_toml = r#"[workspace]

[package]
name = "backseat-payload"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
goblin = "0.10"
libc = "0.2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
"#
    .to_string();
    std::fs::write(vendored_project.join("Cargo.toml"), cargo_toml)
        .expect("failed to write payload Cargo.toml");

    // Copy the vendored source.
    std::fs::copy(&vendored_src, vendored_src_dir.join("lib.rs"))
        .expect("failed to copy payload source");

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--target", &target]);
    if profile == "release" {
        cmd.arg("--release");
    }
    cmd.current_dir(&vendored_project);

    let status = cmd
        .status()
        .expect("failed to spawn cargo build for payload");

    if !status.success() {
        panic!("payload build failed in {}", vendored_project.display());
    }

    let payload_path = vendored_project
        .join("target")
        .join(&target)
        .join(&profile)
        .join("libbackseat_payload.so");

    if !payload_path.exists() {
        panic!(
            "payload build succeeded but artifact not found at {}",
            payload_path.display()
        );
    }

    println!(
        "cargo:rustc-env=BACKSEAT_PAYLOAD_PATH={}",
        payload_path.display()
    );
    println!("cargo:rerun-if-changed={}", payload_path.display());
}
