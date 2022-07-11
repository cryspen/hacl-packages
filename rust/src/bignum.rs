//! Bignum
//!
//! This module implements friendlier bignum for 4096 bit bignums
//!
//! It safely (one hopes) wraps the unsafe Hacl_Bignum operations and provides
//! a struct (type) Bignum that should conceal the nasty pointers to mutable data.

use hacl_rust_sys::*;
use libc;
use std::cmp::Ordering::{Equal, Greater, Less};
use std::fmt;
use std::ptr;

// We need a feature flag for this
type HaclBnWord = u64;
// type HaclBnWord = u32;

#[inline(always)]
unsafe fn free_hacl_bn(bn: HaclBnType) {
    if !bn.is_null() {
        libc::free(bn as *mut libc::c_void);
    }
}

struct HaclBn {
    v: HaclBnType,
}

impl Default for HaclBn {
    fn default() -> Self {
        Self {
            v: ptr::null::<HaclBnType>() as _,
        }
    }
}
impl Drop for HaclBn {
    fn drop(&mut self) {
        unsafe { free_hacl_bn(self.v) }
    }
}

impl fmt::Debug for HaclBn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.v.is_null() {
            true => "is null",
            false => "isn't null",
        };
        write!(f, "HaclBn {}.", msg)
    }
}

/// HaclBnType is used in unsafe operations
type HaclBnType = *mut HaclBnWord;

const BN_BITSIZE: usize = 4096;
const BN_BYTE_LENGTH: usize = BN_BITSIZE / 8;

#[derive(Debug, PartialEq)]
/// Errors for Bignum operations
pub enum Error {
    DeconversionError,
    BadInputLength,
    ConversionError,
    AllocationError,
}

#[derive(Debug)]
pub struct Bignum {
    // There does not appear to be a way to get the size of a hacl_Bignum other
    // than to use the hacl functions for turning one into a byte array.
    // So we will use a byte array as our primary internal representation
    bn: Vec<u8>,
    handle: HaclBn,
}

// We will really want From<whatever-we-use-in-core-for-byte-arrays>

impl PartialEq for Bignum {
    /// Returns true self == other.
    fn eq(&self, other: &Bignum) -> bool {
        let hacl_result: HaclBnWord;
        unsafe {
            hacl_result = Hacl_Bignum4096_eq_mask(self.handle.v, other.handle.v);
        }
        hacl_result != 0 as HaclBnWord
    }
}

unsafe fn get_hacl_bn(bn: Vec<u8>) -> Result<HaclBnType, Error> {
    let data = &mut bn.clone()[..];
    let data_mut_ptr = data.as_mut_ptr();

    let hacl_raw_bn: HaclBnType =
        Hacl_Bignum4096_new_bn_from_bytes_be(bn.len() as u32, data_mut_ptr);
    if hacl_raw_bn.is_null() {
        return Err(Error::AllocationError);
    }
    Ok(hacl_raw_bn)
}

impl Bignum {
    pub fn new(be_bytes: Vec<u8>) -> Result<Self, Error> {
        if !(1..=BN_BYTE_LENGTH).contains(&be_bytes.len()) {
            return Err(Error::BadInputLength);
        }
        let hacl_bn = unsafe { get_hacl_bn(be_bytes.clone())? };

        Ok(Self {
            bn: be_bytes.to_vec(),
            handle: HaclBn { v: hacl_bn },
        })
    }

    /// returns a vector of big-endian bytes
    pub fn to_vec8(&self) -> Vec<u8> {
        self.bn.to_vec()
    }
}

impl PartialOrd for Bignum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let lt_result: HaclBnWord;
        let eq_result: HaclBnWord;
        unsafe {
            lt_result = Hacl_Bignum4096_lt_mask(self.handle.v, other.handle.v);
            eq_result = Hacl_Bignum4096_eq_mask(self.handle.v, other.handle.v);
        }
        if eq_result != 0 as HaclBnWord {
            return Some(Equal);
        } else if lt_result == 0 as HaclBnWord {
            return Some(Greater);
        }
        Some(Less)
    }
}
