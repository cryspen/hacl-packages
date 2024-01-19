extern crate cmake;

use std::env;
use std::path::{Path, PathBuf};

#[cfg(all(not(windows), not(nobindgen)))]
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
        .allowlist_function("Hacl_AEAD_Chacha20Poly1305_.*")
        .allowlist_function("Hacl_Hash_.*")
        .allowlist_function("Hacl_Curve25519_.*")
        .allowlist_function("Hacl_HKDF_.*")
        .allowlist_function("Hacl_HMAC_.*")
        .allowlist_function("Hacl_HMAC_DRBG_.*")
        .allowlist_function("Hacl_Bignum64_.*")
        .allowlist_function("Hacl_Ed25519_.*")
        .allowlist_var("EverCrypt_Error_.*")
        .allowlist_var("Spec_.*")
        .allowlist_type("Spec_.*")
        .allowlist_type("Hacl_HMAC_DRBG_.*")
        .allowlist_type("Hacl_Hash_.*")
        // Block everything we don't need or define ourselves.
        .blocklist_type("EverCrypt_AEAD_state_s.*")
        // These functions currently use FFI-unsafe u128
        .blocklist_type("FStar_UInt128_uint128")
        .blocklist_function("Hacl_Hash_SHA2_update_last_384")
        .blocklist_function("Hacl_Hash_SHA2_update_last_512")
        .blocklist_function("Hacl_Hash_Blake2b_update_multi")
        .blocklist_function("Hacl_Hash_Blake2b_update_last")
        .blocklist_function("Hacl_Hash_Blake2b_Simd256_update_multi")
        .blocklist_function("Hacl_Hash_Blake2b_Simd256_update_last")
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

#[cfg(any(windows, nobindgen))]
fn create_bindings(_: &Path, _: &Path) {}

fn build_hacl_c(path: &Path, cross_target: Option<String>) -> PathBuf {
    eprintln!(" >>> Building HACL C in {}", path.display());

    let mut cmake_cmd = cmake::Config::new(path);

    cmake_cmd.out_dir(path);
    if let Some(toolchain_file) = cross_target.as_deref().and_then(|target| match target {
        "x86_64-apple-darwin" => Some("config/x64-darwin.cmake"),
        "aarch64-apple-darwin" => Some("config/aarch-darwin.cmake"),
        _ => None,
    }) {
        cmake_cmd.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);
    }

    if let Some((cflags, cxxflags)) = cross_target.as_deref().and_then(|target| match target {
        "i686-unknown-linux-gnu" | "i686-pc-windows-msvc" => Some(("-m32", "-m32")),
        _ => None,
    }) {
        cmake_cmd.cflag(cflags).cxxflag(cxxflags);
    }

    cmake_cmd.build()
}

fn copy_hacl_to_out(out_dir: &Path) {
    use fs_extra::{
        dir::{copy, create_all, CopyOptions},
        file,
    };

    let build_dir = out_dir.join("build");
    create_all(&build_dir, true).unwrap();

    let local_c_path = Path::new(".c");
    let options = CopyOptions::new().overwrite(true);

    copy(&local_c_path.join("config"), &out_dir, &options).unwrap();
    copy(&local_c_path.join("src"), &out_dir, &options).unwrap();
    copy(&local_c_path.join("vale"), &out_dir, &options).unwrap();
    copy(&local_c_path.join("karamel"), &out_dir, &options).unwrap();
    copy(&local_c_path.join("include"), &out_dir, &options).unwrap();

    let options = file::CopyOptions::new().overwrite(true);
    file::copy(
        &local_c_path.join("config").join("default_config.cmake"),
        &out_dir.join("build").join("config.cmake"),
        &options,
    )
    .unwrap();
    file::copy(
        &local_c_path.join("CMakeLists.txt"),
        out_dir.join("CMakeLists.txt"),
        &options,
    )
    .unwrap();
}

fn main() {
    // Get ENV variables
    let home_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let home_dir = Path::new(&home_dir);
    let mach_build = env::var("MACH_BUILD").ok().is_some();
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    eprintln!("mach_build: {}", mach_build);

    let cross_target = if target != host {
        Some(target.clone())
    } else {
        None
    };

    // Get the C library and build it first.
    // This is the default behaviour. It can be disabled when working on this
    // to pick up the local version. This is what the global mach script does.
    let hacl_path = if !mach_build {
        // Copy all of the code into out to prepare build
        let c_out_dir = out_dir.join("c");
        if !c_out_dir.join("build").join("installed").exists() {
            eprintln!(" >>> Copying HACL C file");
            eprintln!("     from {}", home_dir.join(".c").display());
            eprintln!("     to {}", c_out_dir.display());
            copy_hacl_to_out(&c_out_dir);
        }
        build_hacl_c(&c_out_dir, cross_target)
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
    // println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");
    // We should re-run if the library changed. But this triggers the build
    // to re-run every time right now.
    // println!(
    //     "cargo:rerun-if-changed={}",
    //     hacl_lib_path.join(library_name).display()
    // );

    // Generate new bindings.
    // This is a no-op on Windows.
    // Also don't build with cfg nobindgen (e.g. on docs.rs because of file system access).
    create_bindings(&hacl_include_path, home_dir);

    // Link hacl library.
    println!("cargo:rustc-link-search=native={}", hacl_lib_path.display());
    println!("cargo:lib={}", hacl_lib_path.display());
    println!("cargo:rustc-link-lib=static={library_name}");
}
