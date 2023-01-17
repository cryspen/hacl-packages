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

pub mod blake2;
pub mod chacha20_poly1305;
pub mod curve25519;
pub mod p256;
pub mod sha2;
pub mod sha3;
