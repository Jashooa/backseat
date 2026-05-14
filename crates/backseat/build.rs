use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let profile = env::var("PROFILE").unwrap();
    let target = env::var("TARGET").unwrap();

    // Re-run if the vendored source changes — even when we end up
    // using the workspace artifact, this guarantees crates.io-based
    // installs pick up vendored changes.
    let vendored_src = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("src")
        .join("payload")
        .join("lib.rs");
    println!("cargo:rerun-if-changed={}", vendored_src.display());

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let crates_dir = manifest_dir.parent().unwrap();
    let workspace_root = crates_dir.parent().unwrap();

    let ws_path = workspace_root
        .join("target")
        .join(&target)
        .join(&profile)
        .join("libbackseat_payload.so");

    let ws_fallback = workspace_root
        .join("target")
        .join(&profile)
        .join("libbackseat_payload.so");

    // Already-built artifact in the workspace target directory?
    if ws_path.exists() {
        emit(&ws_path);
        return;
    }
    if ws_fallback.exists() {
        emit(&ws_fallback);
        return;
    }

    // 1. Try building the workspace package (local dev path).
    let isolated_target = out_dir.join("payload-target");
    let isolated_path = isolated_target
        .join(&target)
        .join(&profile)
        .join("libbackseat_payload.so");

    let ws_success = {
        let mut cmd = Command::new("cargo");
        cmd.args(["build", "-p", "backseat-payload", "--target", &target]);
        if profile == "release" {
            cmd.arg("--release");
        }
        cmd.env("CARGO_TARGET_DIR", &isolated_target);
        cmd.status()
            .expect("failed to spawn cargo build for payload (workspace)")
            .success()
    };

    if ws_success {
        // cargo may have placed the artifact in the workspace target
        // dir despite CARGO_TARGET_DIR, depending on .cargo/config.
        if ws_path.exists() {
            emit(&ws_path);
            return;
        }
        if ws_fallback.exists() {
            emit(&ws_fallback);
            return;
        }
        if isolated_path.exists() {
            emit(&isolated_path);
            return;
        }
        // If we get here the build claimed success but we can't find
        // the artifact.  Fall through to vendored build.
    }

    // 2. Workspace build failed or produced no artifact — we are
    //    likely installed from crates.io.  Build from the vendored
    //    copy of backseat-payload bundled in this crate.
    //
    //    The vendored source lives at src/payload/lib.rs and has no
    //    Cargo.toml (to avoid cargo treating it as a nested package).
    //    We generate a minimal Cargo.toml in a temp directory and copy
    //    the source there, then build.

    let vendored_project = out_dir.join("vendored-payload");
    let vendored_src_dir = vendored_project.join("src");
    std::fs::create_dir_all(&vendored_src_dir).expect("failed to create vendored payload src dir");

    // Generate Cargo.toml in the temp vendored project.
    // Keep deps in sync with crates/backseat-payload/Cargo.toml.
    let cargo_toml = r#"[package]
name = "backseat-payload"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
goblin = "0.10"
libc = "0.2"
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
"#
    .to_string();
    std::fs::write(vendored_project.join("Cargo.toml"), cargo_toml)
        .expect("failed to write vendored Cargo.toml");

    // Copy the vendored source.
    std::fs::copy(&vendored_src, vendored_src_dir.join("lib.rs"))
        .expect("failed to copy vendored payload source");

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--target", &target]);
    if profile == "release" {
        cmd.arg("--release");
    }
    cmd.current_dir(&vendored_project);

    let status = cmd
        .status()
        .expect("failed to spawn cargo build for payload (vendored)");

    if !status.success() {
        panic!(
            "backseat-payload vendored build failed in {}",
            vendored_project.display()
        );
    }

    // The vendored project's target dir defaults to vendored_project/target.
    let vendored_path = vendored_project
        .join("target")
        .join(&target)
        .join(&profile)
        .join("libbackseat_payload.so");

    if vendored_path.exists() {
        emit(&vendored_path);
        return;
    }

    panic!(
        "vendored payload build succeeded but artifact not found at {}",
        vendored_path.display()
    );
}

fn emit(path: &Path) {
    println!("cargo:rustc-env=BACKSEAT_PAYLOAD_PATH={}", path.display());
    println!("cargo:rerun-if-changed={}", path.display());
}
