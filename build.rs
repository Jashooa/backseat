use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let profile = env::var("PROFILE").unwrap();
    let target = env::var("TARGET").unwrap();
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    // Re-run whenever the vendored payload source changes.
    let vendored_src = manifest_dir.join("src").join("payload").join("lib.rs");
    println!("cargo:rerun-if-changed={}", vendored_src.display());
    println!("cargo:rerun-if-changed=build.rs");

    let vendored_project = out_dir.join("payload-project");
    let vendored_src_dir = vendored_project.join("src");
    std::fs::create_dir_all(&vendored_src_dir).expect("failed to create payload src dir");

    // Minimal Cargo.toml — the payload has few deps and they're stable.
    // No goblin, no C shim — the wire rewrite eliminates GOT patching.
    let cargo_toml = r#"[workspace]

[package]
name = "backseat-payload"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
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

    // -----------------------------------------------------------------------
    // Build the dual-mode C test fixture (listener + dispatcher).
    //
    // Compiled directly with the system cc — produces an executable,
    // not a static library.  The binary is available at the path in the
    // BACKSEAT_FIXTURE_C_PATH env var at compile time.
    // -----------------------------------------------------------------------

    let c_fixture_dir = manifest_dir.join("src").join("fixture");
    let fixture_bin_name = "backseat-test-fixture-c";
    let fixture_out = out_dir.join(fixture_bin_name);

    // Re-run if any C source or the vendored protocol header changes.
    println!(
        "cargo:rerun-if-changed={}",
        c_fixture_dir.join("main.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        c_fixture_dir.join("common.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        c_fixture_dir.join("common.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        c_fixture_dir.join("xdg-shell-client-protocol.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        c_fixture_dir.join("xdg-shell-protocol.c").display()
    );

    let cc_status = Command::new("cc")
        .arg(c_fixture_dir.join("common.c"))
        .arg(c_fixture_dir.join("main.c"))
        .arg(c_fixture_dir.join("xdg-shell-protocol.c"))
        .args(["-o", fixture_out.to_str().unwrap()])
        .arg("-I")
        .arg(&c_fixture_dir)
        .args(["-lwayland-client"])
        .status()
        .expect("failed to compile C fixture");

    if !cc_status.success() {
        panic!(
            "C fixture compilation failed.\n\
             Make sure libwayland-dev is installed:\n\
               sudo apt-get install libwayland-dev"
        );
    }

    println!(
        "cargo:rustc-env=BACKSEAT_FIXTURE_C_PATH={}",
        fixture_out.display()
    );
    println!("cargo:rerun-if-changed={}", fixture_out.display());
}
