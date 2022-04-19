//! Utilities that provide randomness.
//! Note that this currently uses the rand crate and should be moved to a more
//! secure alternative.
//!

use rand::{self, thread_rng, Fill, RngCore};
use rand_core::OsRng;

/// Generate a random byte vector of length `len`.
/// *PANICS* if randomness generation fails.
pub fn random_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    out.try_fill(&mut thread_rng()).unwrap();
    out
}

/// Generate a random array.
/// *PANICS* if randomness generation fails.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}
