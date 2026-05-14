use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let profile = env::var("PROFILE").unwrap();
    let target = env::var("TARGET").unwrap();

    let vendored_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("payload");

    // Re-run if the vendored source changes — even when we end up
    // using the workspace artifact, this guarantees crates.io-based
    // installs pick up vendored changes.
    println!(
        "cargo:rerun-if-changed={}",
        vendored_dir.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        vendored_dir.join("src/lib.rs").display()
    );

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
    let vendored_target = out_dir.join("vendored-target");
    let vendored_path = vendored_target
        .join(&target)
        .join(&profile)
        .join("libbackseat_payload.so");

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--target", &target]);
    if profile == "release" {
        cmd.arg("--release");
    }
    cmd.env("CARGO_TARGET_DIR", &vendored_target)
        .current_dir(&vendored_dir);

    let status = cmd
        .status()
        .expect("failed to spawn cargo build for payload (vendored)");

    if !status.success() {
        panic!(
            "backseat-payload vendored build failed in {}",
            vendored_dir.display()
        );
    }

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
