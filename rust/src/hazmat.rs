//! # Low-level HACL APIs
//!
//! No hardware detection, but a safe API to HACL functions.
//!
//! By default only portable APIs are enabled.
//! In order to enable other APIs use `cfg` flags.
//! * simd128 and
//! * simd256
//!
//! |             | x86 | x86-64             | Arm32 | Arm64 | s390x |
//! | ----------- | --- | ------------------ | ----- | ----- | ----- |
//! | Portable C  | ✓   | ✓                  | ✓     | ✓     | ✓     |
//! | simd128     | -   | SSE2, SSE3, SSE4.1 | -     | NEON  | z14   |
//! | simd256     | -   | AVX, AVX2          | -     | -     | -     |

#[cfg(aes_ni)]
pub mod aesgcm;
pub mod blake2;
pub mod chacha20_poly1305;
pub mod curve25519;
pub mod drbg;
pub mod ed25519;
pub mod hkdf;
pub mod hmac;
pub mod p256;
pub mod sha2;
pub mod sha3;

/// Unified error type.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    ChaCha20Poly1305(chacha20_poly1305::Error),
    Curve25519(curve25519::Error),
    P256(p256::Error),
    Ed25519(ed25519::Error),
    Hkdf(hkdf::Error),
}

impl Into<Error> for chacha20_poly1305::Error {
    fn into(self) -> Error {
        Error::ChaCha20Poly1305(self)
    }
}

impl Into<Error> for curve25519::Error {
    fn into(self) -> Error {
        Error::Curve25519(self)
    }
}

impl Into<Error> for p256::Error {
    fn into(self) -> Error {
        Error::P256(self)
    }
}

impl Into<Error> for hkdf::Error {
    fn into(self) -> Error {
        Error::Hkdf(self)
    }
}

impl Into<Error> for ed25519::Error {
    fn into(self) -> Error {
        Error::Ed25519(self)
    }
}
