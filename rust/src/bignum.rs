//! Bignum
//!
//! This module implements friendlier bignum for 4096 bit bignums
//!
//! It safely (one hopes) wraps the unsafe Hacl_Bignum operations and provides
//! a struct (type) Bignum that should conceal the nasty pointers to mutable data.
//!
//! There are some optimizations when the big number is 1 or 0, exposing those
//! to potential side channel attacks. We are assuming that values of 1 and 0 are
//! never meant to be secrets.

use data_encoding::{HEXUPPER, HEXUPPER_PERMISSIVE};
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

impl HaclBnHandle {
    fn to_vec8(&self) -> Result<Vec<u8>, Error> {
        let handle = self.0;
        if self.0.is_null() {
            return Err(Error::NoHandle);
        }

        let be_bytes = &mut [0_u8; Bignum::BN_BYTE_LENGTH];
        unsafe { Hacl_Bignum4096_bn_to_bytes_be(handle, be_bytes.as_mut_ptr()) }

        Ok(be_bytes.to_vec())
    }

    // panics if self isn't a good pointer
    fn zero_one_other(&self) -> ZeroOneOther {
        let be_vec = self.to_vec8().unwrap();
        one_zero_other(&be_vec)
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
        if self.is_one() || self.is_zero() {
            return Ok(Bignum {
                zero_one_other: self.zero_one_other,
                handle: None,
            });
        }
        let old_handle = self.handle.as_ref().unwrap().0;
        let be_bytes = &mut [0_u8; 512];
        unsafe { Hacl_Bignum4096_bn_to_bytes_be(old_handle, be_bytes.as_mut_ptr()) }

        Bignum::new(be_bytes)
    }
}

/// HaclBnType is used in unsafe operations
type HaclBnType = *mut HaclBnWord;

const BN_BITSIZE: usize = 4096;

#[derive(Debug, PartialEq)]
/// Errors for Bignum operations
pub enum Error {
    /// You are trying to convert more bytes than BN_BYTE_LENGTH
    BadInputLength,

    /// Something went wrong when trying to convert to or from a bignum.
    ConversionError,

    /// HACL call returned a null pointer. Probably an allocation error
    AllocationError,

    /// The Bignum is malformed, as it is neither 0, 1, nor has a handle.
    /// This should not happen.
    NoHandle,

    /// The modulus is zero or one. Don't used mod operations in such cases.
    UselessModulus,

    /// You tried to compute 0^0. That is undefined.
    ZeroToZero,

    /// HACL calls sometimes return errors on a variety of conditions.
    /// The best we can do is tell you that this happened.
    HaclError,

    /// data_encoding encountered a decoding error.
    // TODO: Actually pass along the DecodingError
    Decoding,
}

#[derive(Debug)]
pub struct Bignum {
    // There does not appear to be a way to get the size of a hacl_Bignum
    // So we will keep this very unsafe pointer around.
    handle: Option<HaclBnHandle>,

    // I am assuming that a BN of 0 or 1 is never a secret.
    zero_one_other: ZeroOneOther,
}

impl Bignum {
    pub const ONE: Bignum = Bignum {
        zero_one_other: ZeroOneOther::One,
        handle: None,
    };

    pub const ZERO: Bignum = Bignum {
        zero_one_other: ZeroOneOther::Zero,
        handle: None,
    };

    pub const BN_BYTE_LENGTH: usize = BN_BITSIZE / 8;
}

// We will really want From<whatever-we-use-in-core-for-byte-arrays>

impl PartialEq for Bignum {
    /// Returns true self == other.
    fn eq(&self, other: &Bignum) -> bool {
        if self.is_one() && other.is_one() {
            return true;
        }
        if self.is_zero() && other.is_zero() {
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

unsafe fn new_handle(bn: &[u8]) -> Result<HaclBnType, Error> {
    let mut data: [u8; Bignum::BN_BYTE_LENGTH] = [0; Bignum::BN_BYTE_LENGTH];
    let diff_len = Bignum::BN_BYTE_LENGTH - bn.len();
    data[diff_len..].copy_from_slice(bn);

    let hacl_raw_bn: HaclBnType =
        Hacl_Bignum4096_new_bn_from_bytes_be(data.len() as u32, data.as_mut_ptr());
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ZeroOneOther {
    Zero,
    One,
    Other,
}

impl Bignum {
    pub fn new(be_bytes: &[u8]) -> Result<Self, Error> {
        if be_bytes.len() > Bignum::BN_BYTE_LENGTH {
            return Err(Error::BadInputLength);
        }
        match one_zero_other(&trim_left_zero(be_bytes)) {
            ZeroOneOther::One => Ok(Bignum::ONE),
            ZeroOneOther::Zero => Ok(Bignum::ZERO),
            ZeroOneOther::Other => {
                let hacl_bn = unsafe { new_handle(be_bytes)? };
                Ok(Self {
                    zero_one_other: ZeroOneOther::Other,
                    handle: Some(HaclBnHandle(hacl_bn)),
                })
            }
        }
    }

    #[allow(dead_code)]
    fn one_zero_other_true(&self) -> ZeroOneOther {
        // if marked zero or one we trust that, but
        // but we have to check if marked false
        if self.is_one() {
            return ZeroOneOther::One;
        }
        if self.is_zero() {
            return ZeroOneOther::Zero;
        }
        // Now we need to check for false negative.
        // If I could create a static or const Hacl BN for 1 or 0 I would,
        // and I would compare using the HACL library.

        let be_vec = self.to_vec8();
        one_zero_other(&be_vec)
    }

    /// Returns true of our Bignum is 1. False otherwise.
    pub fn is_one(&self) -> bool {
        self.zero_one_other == ZeroOneOther::One
    }
    /// Returns true of our Bignum is 0. False otherwise.
    pub fn is_zero(&self) -> bool {
        self.zero_one_other == ZeroOneOther::Zero
    }

    /// returns a vector of big-endian bytes.
    pub fn to_vec8(&self) -> Vec<u8> {
        match self.zero_one_other {
            ZeroOneOther::One => return VEC_ONE.to_vec(),
            ZeroOneOther::Zero => return VEC_ZERO.to_vec(),
            ZeroOneOther::Other => {}
        }
        // The handle better be good if we aren't zero or one
        let handle = self.handle.as_ref().unwrap();
        handle.to_vec8().unwrap()
    }

    /// A hex representation of the big-endian representation
    pub fn to_hex(&self) -> String {
        let mut be_bytes = trim_left_zero(&self.to_vec8());
        if be_bytes.len() % 2 == 1 {
            // There are probably better ways to do this.
            be_bytes.insert(0, 0_u8);
        }

        HEXUPPER.encode(&be_bytes)
    }
    /// From a hex string
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let be_bytes = HEXUPPER_PERMISSIVE
            .decode(s.as_bytes())
            .map_err(|_| Error::Decoding)?;

        Self::new(&be_bytes)
    }
}

// Now the math

impl PartialOrd for Bignum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if (self.is_one() && other.is_one()) || (self.is_zero() && other.is_zero()) {
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

// More math.
impl Bignum {
    // We will try to use the same function signatures as exist in
    // num-bigint::BigUint, except that we will wrap in Results where
    // num-bigint panics
    // https://docs.rs/num-bigint/latest/num_bigint/struct.BigUint.html

    pub fn modpow(&self, exponent: &Self, modulus: &Self) -> Result<Self, Error> {
        //! Returns (self ^ exponent) % modulus.
        //!
        //! # Errors
        //! - Error if modulus < 2.
        //! - Error if both self and exponent are zero.
        //! - Error if
        //!     * modulus is even
        //!     * self is not less than modulus
        //!
        //! # Security
        //! We are assuming that we can leak timing information if base or exponent
        //! are 1 or 0.

        if self.is_zero() && exponent.is_zero() {
            return Err(Error::ZeroToZero);
        }
        if modulus.is_zero() || modulus.is_one() {
            return Err(Error::UselessModulus);
        }

        if self.is_zero() {
            return Ok(Bignum::ZERO);
        }
        if self.is_one() {
            return Ok(Bignum::ONE);
        }
        if exponent.is_zero() {
            return Ok(Bignum::ONE);
        }
        if exponent.is_one() {
            return self.try_clone();
        }

        // We should now be in a state in which we know that base and exponent
        // are greater than 1, so we need call Hacl_Bignum4096_mod_exp_consttime

        // let's get the Hacl parameters (and with the names used by HACL)
        // a^b mod n into res
        let n = modulus.handle.as_ref().ok_or(Error::NoHandle)?.0;
        let a = self.handle.as_ref().ok_or(Error::NoHandle)?.0;
        let b = exponent.handle.as_ref().ok_or(Error::NoHandle)?.0;

        // I still can't find a way to get the size of Hacl bignnums, so will
        // just use the maximum
        #[allow(non_snake_case)]
        let bBits = 8 * Self::BN_BYTE_LENGTH;

        let mut res: [u64; BN_BITSIZE / 64] = [0; BN_BITSIZE / 64];

        let hacl_ret_val: bool;
        unsafe {
            hacl_ret_val =
                Hacl_Bignum4096_mod_exp_consttime(n, a, bBits as u32, b, res.as_mut_ptr())
        }
        if !hacl_ret_val {
            return Err(Error::HaclError);
        }
        let handle: HaclBnHandle = HaclBnHandle(res.as_mut_ptr());
        let zero_one_other = handle.zero_one_other();

        Ok(Self {
            zero_one_other,
            handle: Some(handle),
        })
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
            TestVector {
                a: vec![0_u8, 0, 1, 0, 7],
                b: vec![0_u8, 1, 0, 6],
                expected: false,
                expected_a_len: 3,
                name: "(263,262), len(4,5)",
            },
            TestVector {
                a: vec![0_u8, 0, 2, 0],
                b: vec![0_u8, 0, 0, 2],
                expected: false,
                expected_a_len: 2,
                name: "(512,2), len(4,4)",
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
                a_trim,
                b_trim
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
