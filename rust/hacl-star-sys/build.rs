#[cfg(not(windows))]
extern crate bindgen;

use std::{env, path::Path, process::Command};

#[cfg(not(windows))]
fn create_bindings(include_path: &Path, home_dir: &Path) {
    // Include paths
    let hacl_includes = vec![
        format!("-I{}", include_path.display()),
        format!("-I{}", include_path.join("hacl").display()),
        format!("-I{}", include_path.join("krml").display()),
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
        .allowlist_function("Hacl_RSAPSS_.*")
        .allowlist_function("Hacl_SHA3_.*")
        .allowlist_var("EverCrypt_Error_.*")
        .allowlist_var("Spec_.*")
        .allowlist_type("Spec_.*")
        // Block everything we don't need or define ourselves.
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

fn build_hacl_c(path: &Path, cross_target: Option<String>) {
    println!(" >>> Building HACL C in {}", path.display());
    // cmake
    let mut cmake_cmd = Command::new("cmake");

    // Map cross compile targets to cmake toolchain files
    let toolchain_file = cross_target
        .map(|s| match s.as_str() {
            "x86_64-apple-darwin" => "-DCMAKE_TOOLCHAIN_FILE=config/x64-darwin.cmake",
            "aarch64-apple-darwin" => "-DCMAKE_TOOLCHAIN_FILE=config/aarch64-darwin.cmake",
            _ => "",
        })
        .unwrap_or_default();

    // We always build the release version here.
    // TODO: For debugging don't use this.
    let cmake_status = cmake_cmd
        .current_dir(path)
        .args(&[
            "-B",
            "build",
            "-G",
            "Ninja",
            "-D",
            "CMAKE_BUILD_TYPE=Release",
            toolchain_file,
        ])
        .status()
        .expect("Failed to run cmake.");
    if !cmake_status.success() {
        panic!("Failed to run cmake.")
    }
    // build
    let mut ninja_cmd = Command::new("ninja");
    let ninja_status = ninja_cmd
        .current_dir(path)
        .args(&["-f", "build.ninja", "-C", "build"])
        .status()
        .expect("Failed to run ninja.");
    if !ninja_status.success() {
        panic!("Failed to run ninja.")
    }

    // install
    let install_path = path.join("build").join("installed");
    println!(" >>> Installing HACL C into {}", install_path.display());
    let mut cmake_cmd = Command::new("cmake");
    let cmake_status = cmake_cmd
        .current_dir(path)
        .args(&[
            "--install",
            "build",
            "--prefix",
            install_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to install C library.");
    if !cmake_status.success() {
        panic!("Failed to install C library.")
    }
}

fn main() {
    // Get ENV variables
    let home_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let home_dir = Path::new(&home_dir);
    let mach_build = env::var("MACH_BUILD").ok().is_some();
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    println!("mach_build: {}", mach_build);

    let cross_target = if target != host { Some(target) } else { None };

    // Get the C library and build it first.
    // This is the default behaviour. It can be disabled when working on this
    // to pick up the local version. This is what the global mach script does.
    let hacl_path = if !mach_build {
        // Check if we have to copy the C files first.
        if !home_dir.join("..").join(".c").exists() {
            println!(" >>> Copying HACL C file");
            // ./mach rust
            let mut mach_cmd = Command::new("./mach");
            let mach_status = mach_cmd
                .current_dir(home_dir.join("..").join(".."))
                .args(&["rust"])
                .status()
                .expect("Failed to run ./mach rust.");
            if !mach_status.success() {
                panic!("Failed to run ./mach rust.")
            }
        }
        let c_path = home_dir.join("..").join(".c");
        build_hacl_c(&c_path, cross_target);
        c_path.join("build").join("installed")
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
