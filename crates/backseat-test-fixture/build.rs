fn main() {
    // Force lazy PLT binding so our ptrace-injected payload can interpose
    // libwayland-client symbols.  Without this, the fixture binary is
    // compiled BIND_NOW and all PLT entries are resolved before injection.
    println!("cargo:rustc-link-arg=-Wl,-z,lazy");
}
