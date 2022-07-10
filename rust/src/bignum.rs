//! Bignum
//!
//! This module implements friendlier bignum for 4096 bit bignums
//!
//! It safely (one hopes) wraps the unsafe Hacl_Bignum operations and provides
//! a struct (type) Bignum that should conceal the nasty pointers to mutable data.

use hacl_rust_sys::*;
use libc;
use std::mem;
use std::slice;

// We need a feature flag for this
type HaclBnWord = u64;
// type HaclBnWord = u32;

const BYTES_PER_WORD: usize = mem::size_of::<HaclBnWord>();
const BN_BITSIZE: usize = 4096;

const BN_SLICE_LENGTH: usize = BN_BITSIZE / (BYTES_PER_WORD * 8);
const BN_BYTE_LENGTH: usize = BN_BITSIZE / 8;

#[derive(Debug)]
/// Errors for Bignum operations
pub enum Error {
    DeconversionError,
    ConversionError,
    AllocationError,
}

/// HaclBnType is used in unsafe operations
type HaclBnType = *mut HaclBnWord;

#[derive(Debug)]
pub struct Bignum {
    // There does not appear to be a way to get the size of a hacl_Bignum other
    // than to use the hacl functions for turning one into a byte array.
    // So we will use a byte array as our primary internal representation
    bn: Vec<u8>,

    // hacl_bn is a slice that is the Rust-friendly version of their `*mut u64`
    // It is designed to be converted into what the FFI wants without having to
    // go through Hacl_Bignum4096_new_bn_from_bytes_be each time.
    hacl_bn: Vec<HaclBnWord>,
}

// We will really want From<whatever-we-use-in-core-for-byte-arrays>
impl TryFrom<&[u8]> for Bignum {
    type Error = Error;
    fn try_from(be_bytes: &[u8]) -> Result<Bignum, Error> {
        let length: u32 = be_bytes.len() as u32;

        let bn: Vec<u8>;
        let hacl_bn: Vec<HaclBnWord>;

        unsafe {
            // Let's create a short-lived mutable clone of our big endian input
            let data = vec![0u8; be_bytes.len()].as_mut_ptr();

            let raw_bn = vec![0u8; BN_BYTE_LENGTH].as_mut_ptr();

            let hacl_raw_bn: HaclBnType = Hacl_Bignum4096_new_bn_from_bytes_be(length, data);
            if hacl_raw_bn.is_null() {
                return Err(Error::AllocationError);
            }

            hacl_bn = slice::from_raw_parts_mut(hacl_raw_bn, BN_SLICE_LENGTH).to_vec();

            Hacl_Bignum4096_bn_to_bytes_be(hacl_raw_bn, raw_bn);
            libc::free(hacl_raw_bn as *mut libc::c_void);
            bn = Vec::from_raw_parts(raw_bn, BN_BYTE_LENGTH, BN_BYTE_LENGTH);
        };

        Ok(Self { bn, hacl_bn })
    }
}

impl Bignum {
    /// returns a vector of big-endian bytes
    pub fn to_vec8(&self) -> Vec<u8> {
        self.bn.to_vec()
    }

    /// Returns true if self < other
    pub fn lt(&self, other: &Bignum) -> bool {
        // We probably don't need to clone() here, as I don't think that the
        // data is actually mutated. But let's be careful here.
        let a = self.hacl_bn.clone().as_mut_ptr();
        let b = other.hacl_bn.clone().as_mut_ptr();

        let hacl_result: HaclBnWord;
        unsafe {
            hacl_result = Hacl_Bignum4096_lt_mask(a, b);
        }
        hacl_result != 0 as HaclBnWord
    }
}
