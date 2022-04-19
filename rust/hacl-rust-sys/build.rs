#[cfg(not(windows))]
extern crate bindgen;

use std::{env, path::Path, process::Command};

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
fn create_bindings(_: &Path, _: &Path) {}

fn get_hacl_c(out_path: &Path) {
    // git clone the repo
    if out_path.join("hacl-packages").exists() {
        // Only clone if we didn't do so already.
        return;
    }
    let mut mach_cmd = Command::new("git");
    let mach_status = mach_cmd
        .current_dir(out_path)
        .args(&[
            "clone",
            "https://github.com/cryspen/hacl-packages",
            "--depth=1",
        ])
        .status()
        .expect("Failed to run git clone.");
    if !mach_status.success() {
        panic!("Failed to run git clone.")
    }
    println!(" >>> Cloned hacl-packages into {}", out_path.display())
}

fn build_hacl_c(path: &Path) {
    println!(" >>> Building HACL C in {}", path.display());
    let canon_mach = std::fs::canonicalize(path.join("mach")).expect("Failed to find mach script!");
    let mut mach_cmd = Command::new(canon_mach.clone());
    let mach_status = mach_cmd
        .current_dir(path)
        // We always build the release version here.
        // For debugging don't use this.
        .args(&["build", "--release"])
        .status()
        .expect("Failed to run mach build.");
    if !mach_status.success() {
        panic!("Failed to run mach build.")
    }
    let install_path = path.join("build").join("installed");
    println!(" >>> Installing HACL C into {}", install_path.display());
    let mut mach_cmd = Command::new(canon_mach);
    let mach_status = mach_cmd
        .current_dir(path)
        .args(&[
            "install",
            "--prefix",
            install_path.to_str().unwrap(),
            "-c",
            "release",
        ])
        .status()
        .expect("Failed to run mach install.");
    if !mach_status.success() {
        panic!("Failed to run mach install.")
    }
}

fn main() {
    // Get ENV variables
    let home_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let home_dir = Path::new(&home_dir);
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);
    let mach_build = env::var("MACH_BUILD").ok().is_some();
    println!("mach_build: {}", mach_build);

    // Get the C library and build it first.
    // This is the default behaviour. It can be disabled when working on this
    // to pick up the local version. This is what the global mach script does.
    let hacl_path = if !mach_build {
        get_hacl_c(&out_path);
        let hacl_packages_path = out_path.join("hacl-packages");
        build_hacl_c(&hacl_packages_path);
        hacl_packages_path.join("build").join("installed")
    } else {
        // Use the higher level install directory.
        home_dir
            .join("..")
            .join("..")
            .join("build")
            .join("installed")
    };
    let hacl_lib_path = hacl_path.join("lib");
    let hacl_include_path = hacl_path.join("include");

    // Set library name to look up
    let library_name = "hacl_static";

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
