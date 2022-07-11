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
        Self {v: ptr::null::<HaclBnType>() as _ }
    }
}
impl Drop for HaclBn {
    fn drop(&mut self) {
         unsafe { free_hacl_bn(self.v)}
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
impl TryFrom<Vec<u8>> for Bignum {
    type Error = Error;
    fn try_from(be_bytes: Vec<u8>) -> Result<Bignum, Error> {
        if !(1..=BN_BYTE_LENGTH).contains(&be_bytes.len()) {
            return Err(Error::BadInputLength);
        }
        let bytes: &mut [u8] = &mut be_bytes.clone()[..];
        let mut handle = HaclBn::default();
        unsafe {
            handle.v =
                Hacl_Bignum4096_new_bn_from_bytes_be(bytes.len() as u32, bytes.as_mut_ptr());
            if handle.v.is_null() {
                return Err(Error::ConversionError);
            }
        }
        Ok(Self {
            bn: be_bytes.to_vec(),
            handle,
        })
    }
}

impl PartialEq for Bignum {
    /// Returns true self == other.
    /// Returns false if there is a problem obtaining the hacl pointers
    /// for either self or other (hence this is _Partial_ Eq).
    fn eq(&self, other: &Bignum) -> bool {
        // We can't just compare on self.bn, as we would want
        // !vec[0, 5] != !vec[5] even though the big numbers they
        // represent are the same.
        let hacl_result: HaclBnWord;
        unsafe {
            let a = self.get_hacl_bn();
            let a: HaclBnType = match a {
                Ok(x) => x,
                Err(_) => return false,
            };
            let b = other.get_hacl_bn();
            let b = match b {
                Ok(x) => x,
                Err(_) => {
                    free_hacl_bn(a);
                    return false;
                }
            };

            hacl_result = Hacl_Bignum4096_eq_mask(a, b);
            free_hacl_bn(a);
            free_hacl_bn(b);
        }
        hacl_result != 0 as HaclBnWord
    }
}

impl Bignum {
    /// returns a vector of big-endian bytes
    pub fn to_vec8(&self) -> Vec<u8> {
        self.bn.to_vec()
    }

    // This returns a pointer to an unknown amount of data
    unsafe fn get_hacl_bn(&self) -> Result<HaclBnType, Error> {
        let data = &mut self.bn.clone()[..];
        let data_mut_ptr = data.as_mut_ptr();

        let hacl_raw_bn: HaclBnType =
            Hacl_Bignum4096_new_bn_from_bytes_be(self.bn.len() as u32, data_mut_ptr);
        if hacl_raw_bn.is_null() {
            return Err(Error::AllocationError);
        }
        Ok(hacl_raw_bn)
    }
}

impl PartialOrd for Bignum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let lt_result: HaclBnWord;
        let eq_result: HaclBnWord;
        unsafe {
            let a = self.get_hacl_bn();
            let a: HaclBnType = match a {
                Ok(x) => x,
                Err(_) => return None,
            };
            let b = other.get_hacl_bn();
            let b = match b {
                Ok(x) => x,
                Err(_) => {
                    free_hacl_bn(a);
                    return None;
                }
            };
            lt_result = Hacl_Bignum4096_lt_mask(a, b);
            eq_result = Hacl_Bignum4096_eq_mask(a, b);
            free_hacl_bn(a);
            free_hacl_bn(b);
        }
        if eq_result == 0 as HaclBnWord {
            return Some(Equal);
        } else if lt_result == 0 as HaclBnWord {
            return Some(Greater);
        }
        Some(Less)
    }

    fn lt(&self, other: &Self) -> bool {
        matches!(self.bn.partial_cmp(&other.bn), Some(Less))
    }

    fn le(&self, other: &Self) -> bool {
        // Pattern `Some(Less | Eq)` optimizes worse than negating `None | Some(Greater)`.
        // FIXME: The root cause was fixed upstream in LLVM with:
        // https://github.com/llvm/llvm-project/commit/9bad7de9a3fb844f1ca2965f35d0c2a3d1e11775
        // Revert this workaround once support for LLVM 12 gets dropped.
        !matches!(self.partial_cmp(other), None | Some(Greater))
    }

    fn gt(&self, other: &Self) -> bool {
        matches!(self.partial_cmp(other), Some(Greater))
    }

    fn ge(&self, other: &Self) -> bool {
        matches!(self.partial_cmp(other), Some(Greater | Equal))
    }
}
