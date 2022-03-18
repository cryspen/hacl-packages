#[cfg(not(windows))]
extern crate bindgen;

use std::{env, path::Path};

#[cfg(not(windows))]
fn create_bindings(include_path: &Path, home_dir: &Path) {
    // Include paths
    let hacl_includes = vec![
        format!("-I{}", include_path.display()),
        format!("-I{}", include_path.join("hacl").display()),
        format!("-I{}", include_path.join("kremlin").display()),
        format!("-I{}", include_path.join("vale").display()),
    ];

    let bindings = bindgen::Builder::default()
        // Header to wrap HACL/Evercrypt headers
        .header("wrapper.h")
        // Set include paths for HACL/Evercrypt headers
        .clang_args(hacl_includes.iter())
        // Allow function we want to have in
        .allowlist_function("EverCrypt_AutoConfig2_.*")
        .allowlist_function("EverCrypt_AEAD_.*")
        .allowlist_function("EverCrypt_Curve25519_.*")
        .allowlist_function("EverCrypt_Ed25519_.*")
        .allowlist_function("EverCrypt_Hash_.*")
        .allowlist_function("EverCrypt_HKDF_.*")
        .allowlist_function("EverCrypt_HMAC_.*")
        .allowlist_function("Hacl_P256_.*")
        .allowlist_function("Hacl_SHA3_.*")
        .allowlist_var("EverCrypt_Error_.*")
        .allowlist_var("Spec_.*")
        .allowlist_type("Spec_.*")
        // Block everything we don't need or define ourselves.
        .blocklist_type("Hacl_Streaming_.*")
        .blocklist_type("EverCrypt_AEAD_state_s.*")
        // Disable tests to avoid warnings and keep it portable
        .layout_tests(false)
        // Generate bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // let bindings_path = out_path.join("bindings.rs");
    let home_bindings = home_dir.join("src/bindings/bindings.rs");
    bindings
        .write_to_file(home_bindings)
        .expect("Couldn't write bindings!");
}

#[cfg(windows)]
fn create_bindings(_: &str) {}

fn main() {
    // Get ENV variables
    let home_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let home_dir = Path::new(&home_dir);
    let target = env::var("TARGET").unwrap();

    // Set library name to look up
    let library_name = if target == "x86_64-pc-windows-msvc" {
        "libhacl_static"
    } else {
        "hacl_static"
    };

    // Set HACL paths
    let hacl_path = home_dir
        .join("..")
        .join("..")
        .join("build")
        .join("installed");
    let hacl_lib_path = hacl_path.join("lib");
    let hacl_include_path = hacl_path.join("include");

    // Set re-run trigger
    println!("cargo:rerun-if-changed=wrapper.h");
    // We should re-run if the library changed. But this triggers the build
    // to re-run every time right now.
    // println!(
    //     "cargo:rerun-if-changed={}",
    //     hacl_lib_path.join(library_name).display()
    // );

    // Generate new bindings. This is a no-op on Windows.
    create_bindings(&hacl_include_path, home_dir);

    // Link hacl library.
    let mode = "static";
    println!("cargo:rustc-link-lib={}={}", mode, library_name);
    println!("cargo:rustc-link-search=native={}", hacl_lib_path.display());
    println!("cargo:lib={}", hacl_lib_path.display());
}
