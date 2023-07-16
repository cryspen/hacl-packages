#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn simd128_support(target: &str) -> bool {
    if target != "x86_64" {
        // We don't want any SIMD for x86 for now when cross compiling.
        return false;
    }

    std::arch::is_x86_feature_detected!("sse2")
        && std::arch::is_x86_feature_detected!("sse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
        && std::arch::is_x86_feature_detected!("avx")
}

#[cfg(target_arch = "aarch64")]
fn simd128_support(_target: &str) -> bool {
    true
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
fn simd128_support(_target: &str) -> bool {
    // XXX: Check for z14 or z15
    false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn simd256_support(target: &str) -> bool {
    if target != "x86_64" {
        // We don't want any SIMD for x86 for now when cross compiling.
        return false;
    }

    std::arch::is_x86_feature_detected!("avx2")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn simd256_support(_target: &str) -> bool {
    // XXX: Check for z14 or z15
    false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn bmi2_adx_support(target: &str) -> bool {
    if target != "x86_64" {
        // We don't want any SIMD for x86 for now when cross compiling.
        return false;
    }

    std::arch::is_x86_feature_detected!("bmi2") && std::arch::is_x86_feature_detected!("adx")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn bmi2_adx_support(_target: &str) -> bool {
    false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn sha_ni_support(target: &str) -> bool {
    if target != "x86_64" {
        // We don't want any SIMD for x86 for now when cross compiling.
        return false;
    }

    std::arch::is_x86_feature_detected!("sha")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn sha_ni_support(_target: &str) -> bool {
    false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn aes_ni_support(target: &str) -> bool {
    if target != "x86_64" {
        // We don't want any SIMD for x86 for now when cross compiling.
        return false;
    }

    // Note that we don't check for "movbe" here.
    // This will be checked only on runtime.
    // This is good enough here for the build.
    std::arch::is_x86_feature_detected!("avx")
        && std::arch::is_x86_feature_detected!("sse")
        && std::arch::is_x86_feature_detected!("aes")
        && std::arch::is_x86_feature_detected!("pclmulqdq")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn aes_ni_support(_target: &str) -> bool {
    false
}

fn main() {
    // We can't use cfg for cross compilation because the build script is compiled
    // for the host.
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    eprintln!("Building for {target_arch}");

    if simd128_support(&target_arch) {
        println!("cargo:rustc-cfg=simd128");
    }
    if simd256_support(&target_arch) {
        println!("cargo:rustc-cfg=simd256");
    }
    if bmi2_adx_support(&target_arch) {
        println!("cargo:rustc-cfg=bmi2");
        println!("cargo:rustc-cfg=adx");
    }
    if sha_ni_support(&target_arch) {
        println!("cargo:rustc-cfg=sha_ni");
    }
    if aes_ni_support(&target_arch) {
        println!("cargo:rustc-cfg=aes_ni");
    }
}
