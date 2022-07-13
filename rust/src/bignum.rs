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

struct HaclBnHandle(HaclBnType);

impl Default for HaclBnHandle {
    fn default() -> Self {
        Self(ptr::null::<HaclBnType>() as _)
    }
}
impl Drop for HaclBnHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                libc::free(self.0 as *mut libc::c_void);
            }
        }
    }
}

impl fmt::Debug for HaclBnHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.0.is_null() {
            true => "is null",
            false => "isn't null",
        };
        write!(f, "HaclBn {}.", msg)
    }
}

impl Bignum {
    /// Attempts to create a new Bignum with the same values.
    /// Allocates new memory with a new pointer to that memory
    pub fn try_clone(&self) -> Result<Self, Error> {
        if self.is_one || self.is_zero {
            return Ok(Bignum {
                is_one: self.is_one,
                is_zero: self.is_zero,
                handle: None,
            });
        }
        let old_handle = self.handle.as_ref().unwrap().0;
        let be_bytes = &mut [0_u8; 512];
        unsafe { Hacl_Bignum4096_bn_to_bytes_be(old_handle, be_bytes.as_mut_ptr()) }

        Bignum::new(be_bytes.to_vec())
    }
}

/// HaclBnType is used in unsafe operations
type HaclBnType = *mut HaclBnWord;

const BN_BITSIZE: usize = 4096;
const BN_BYTE_LENGTH: usize = BN_BITSIZE / 8;

#[derive(Debug, PartialEq)]
/// Errors for Bignum operations
pub enum Error {
    BadInputLength,
    ConversionError,
    AllocationError,
}

#[derive(Debug)]
pub struct Bignum {
    // There does not appear to be a way to get the size of a hacl_Bignum
    // So we will keep this very unsafe pointer around.
    handle: Option<HaclBnHandle>,

    // I am assuming that a BN of 0 or 1 is never a secret.
    is_zero: bool,
    is_one: bool,
}

const ONE: Bignum = Bignum {
    is_one: true,
    is_zero: false,
    handle: None,
};

const ZERO: Bignum = Bignum {
    is_one: false,
    is_zero: true,
    handle: None,
};

// We will really want From<whatever-we-use-in-core-for-byte-arrays>

impl PartialEq for Bignum {
    /// Returns true self == other.
    fn eq(&self, other: &Bignum) -> bool {
        if self.is_one && other.is_one {
            return true;
        }
        if self.is_zero && other.is_zero {
            return true;
        }

        let a_handle = match &self.handle {
            None => return false,
            Some(x) => x.0,
        };
        let b_handle = match &other.handle {
            None => return false,
            Some(x) => x.0,
        };

        let hacl_result: HaclBnWord;
        unsafe {
            hacl_result = Hacl_Bignum4096_eq_mask(a_handle, b_handle);
        }
        hacl_result != 0 as HaclBnWord
    }
}

unsafe fn get_hacl_bn(bn: Vec<u8>) -> Result<HaclBnType, Error> {
    let data = &mut bn.clone()[..];

    let hacl_raw_bn: HaclBnType =
        Hacl_Bignum4096_new_bn_from_bytes_be(bn.len() as u32, data.as_mut_ptr());
    if hacl_raw_bn.is_null() {
        return Err(Error::AllocationError);
    }
    Ok(hacl_raw_bn)
}

// Some Vec<u8> utilities

const VEC_ONE: [u8; 1] = [1_u8];
const VEC_ZERO: [u8; 1] = [0_u8];

// This could be done for any Vec<T>
// with second argument that is T -> bool,
// but let me just do this the very concrete way.
fn trim_left_zero(v: &[u8]) -> Vec<u8> {
    let r: Vec<u8> = v.iter().copied().skip_while(|x| *x == 0_u8).collect();

    if r.is_empty() {
        VEC_ZERO.to_vec()
    } else {
        r
    }
}

fn one_zero_other(v: &[u8]) -> ZeroOneOther {
    let b = trim_left_zero(v);
    if b.eq(&VEC_ONE) {
        ZeroOneOther::One
    } else if b.eq(&VEC_ZERO) {
        ZeroOneOther::Zero
    } else {
        ZeroOneOther::Other
    }
}

enum ZeroOneOther {
    Zero,
    One,
    Other,
}

impl Bignum {
    pub fn new(be_bytes: Vec<u8>) -> Result<Self, Error> {
        let bn = trim_left_zero(&be_bytes);
        if bn.len() > BN_BYTE_LENGTH {
            return Err(Error::BadInputLength);
        }
        match one_zero_other(&bn) {
            ZeroOneOther::One => Ok(ONE),
            ZeroOneOther::Zero => Ok(ZERO),
            ZeroOneOther::Other => {
                let hacl_bn = unsafe { get_hacl_bn(bn.clone())? };
                Ok(Self {
                    is_one: false,
                    is_zero: false,
                    handle: Some(HaclBnHandle(hacl_bn)),
                })
            }
        }
    }

    /// returns a vector of big-endian bytes
    pub fn to_vec8(&self) -> Vec<u8> {
        if self.is_one {
            return VEC_ONE.to_vec();
        }
        if self.is_zero {
            return VEC_ZERO.to_vec();
        }

        // The handle better be good if we aren't zero or one
        let handle = self.handle.as_ref().unwrap().0;

        let be_bytes = &mut [0_u8; 512];
        unsafe { Hacl_Bignum4096_bn_to_bytes_be(handle, be_bytes.as_mut_ptr()) }

        trim_left_zero(&be_bytes.to_vec())
    }
}

// Now the math

impl PartialOrd for Bignum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if (self.is_one && other.is_one) || (self.is_zero && other.is_zero) {
            return Some(Equal);
        }
        let a_handle = match &self.handle {
            None => return None,
            Some(h) => h.0,
        };
        let b_handle = match &other.handle {
            None => return None,
            Some(h) => h.0,
        };

        let lt_result: HaclBnWord;
        let eq_result: HaclBnWord;
        unsafe {
            lt_result = Hacl_Bignum4096_lt_mask(a_handle, b_handle);
            eq_result = Hacl_Bignum4096_eq_mask(a_handle, b_handle);
        }
        if eq_result != 0 as HaclBnWord {
            return Some(Equal);
        } else if lt_result == 0 as HaclBnWord {
            return Some(Greater);
        }
        Some(Less)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_trim_left_zero() {
        struct TestVector<'a> {
            a: Vec<u8>,
            b: Vec<u8>,
            expected: bool,
            expected_a_len: usize,
            name: &'a str,
        }

        let tests = vec![
            TestVector {
                a: vec![0_u8],
                b: vec![0_u8],
                expected: true,
                expected_a_len: 1,
                name: "(0,0), len(1,1)",
            },
            TestVector {
                a: vec![0_u8, 0],
                b: vec![0_u8],
                expected: true,
                expected_a_len: 1,
                name: "(0,0), len(2,1)",
            },
            TestVector {
                a: vec![0_u8, 1],
                b: vec![0_u8, 0], 
                expected: false,
                expected_a_len: 1,
                name: "(1,0), len(2,2)",
            },
            TestVector {
                a: vec![0_u8, 0, 1, 0],
                b: vec![0_u8, 1, 0],
                expected: true,
                expected_a_len: 2,
                name: "(256,256), len(3,2)",
            },
        ];
        for t in tests {
            let a_trim = trim_left_zero(&t.a);
            let b_trim = trim_left_zero(&t.b);

            let equal_trims = a_trim == b_trim;
            assert!(
                equal_trims == t.expected,
                "Expected {} for {}. A: {:?}. B: {:?}",
                t.expected,
                t.name,
                a_trim, b_trim
            );

            let a_trim_len = a_trim.len();
            let exp_a_len = t.expected_a_len;
            assert!(
                a_trim_len == exp_a_len,
                "Expected len ({}) != len({}) for {}",
                exp_a_len,
                a_trim_len,
                t.name
            );
        }
    }
}
