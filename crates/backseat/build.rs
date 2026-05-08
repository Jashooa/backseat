use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
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
            // Automatically build the payload if it's missing.
            // We use a separate target directory to avoid Cargo workspace locks.
            let mut cmd = Command::new("cargo");
            cmd.args(["build", "-p", "backseat-payload", "--target", &target]);
            if profile == "release" {
                cmd.arg("--release");
            }

            // Set CARGO_TARGET_DIR to a subdirectory of OUT_DIR so we don't
            // contend with the main workspace lock.
            cmd.env("CARGO_TARGET_DIR", out_dir.join("payload-target"));

            let status = cmd
                .status()
                .expect("failed to spawn cargo build for payload");
            if !status.success() {
                panic!("backseat-payload build failed");
            }

            // Try the original path again (cargo may have placed it in the
            // workspace target dir despite CARGO_TARGET_DIR, depending on
            // whether a .cargo/config overrides it).
            if payload_path.exists() {
                payload_path
            } else if fallback.exists() {
                fallback
            } else {
                // Try the isolated target dir
                let isolated = out_dir
                    .join("payload-target")
                    .join(&target)
                    .join(&profile)
                    .join("libbackseat_payload.so");
                if isolated.exists() {
                    isolated
                } else {
                    panic!(
                        "backseat-payload build succeeded but artifact not found at expected locations"
                    );
                }
            }
        }
    };

    println!(
        "cargo:rustc-env=BACKSEAT_PAYLOAD_PATH={}",
        payload_path.display()
    );
    println!("cargo:rerun-if-changed={}", payload_path.display());
}
