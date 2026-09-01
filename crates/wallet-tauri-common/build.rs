//! Make this crate's test executables loadable on Windows.
//!
//! See `windows-test.manifest`: the Tauri window layer imports four Common
//! Controls v6 entry points, a cargo test executable asks for no Common
//! Controls version, and the Windows loader therefore refuses to start it.
//! This applies to test targets only. Nothing about the shipped application
//! changes.
fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=windows-test.manifest");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    let manifest = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("windows-test.manifest");
    println!("cargo::rustc-link-arg-tests=/MANIFEST:EMBED");
    println!(
        "cargo::rustc-link-arg-tests=/MANIFESTINPUT:{}",
        manifest.display()
    );
}
