//! Bignum
//!
//! This module implements friendlier bignum for 4096 bit bignums
//!
//! It safely (one hopes) wraps the unsafe Hacl_Bignum operations and provides
//! a struct (type) Bignum that should conceal the nasty pointers to mutable data.

use hacl_rust_sys::*;
use libc;

// We need a feature flag for this
type HaclBnWord = u64;
// type HaclBnWord = u32;

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

/// HaclBnType is used in unsafe operations
type HaclBnType = *mut HaclBnWord;

#[derive(Debug)]
pub struct Bignum {
    // There does not appear to be a way to get the size of a hacl_Bignum other
    // than to use the hacl functions for turning one into a byte array.
    // So we will use a byte array as our primary internal representation
    bn: Vec<u8>,
}

// We will really want From<whatever-we-use-in-core-for-byte-arrays>
impl TryFrom<Vec<u8>> for Bignum {
    type Error = Error;
    fn try_from(be_bytes: Vec<u8>) -> Result<Bignum, Error> {
        if !(1..=BN_BYTE_LENGTH).contains(&be_bytes.len()) {
            return Err(Error::BadInputLength);
        }
        Ok(Self {
            bn: be_bytes.to_vec(),
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

#[inline(always)]
unsafe fn free_hacl_bn(bn: HaclBnType) {
    if !bn.is_null() {
        libc::free(bn as *mut libc::c_void);
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

    /// Returns true if self < other
    pub fn lt(&self, other: &Bignum) -> Result<bool, Error> {
        let hacl_result: HaclBnWord;
        unsafe {
            let a = self.get_hacl_bn()?;
            let b = other.get_hacl_bn()?;
            hacl_result = Hacl_Bignum4096_lt_mask(a, b);
            free_hacl_bn(a);
            free_hacl_bn(b);
        }
        Ok(hacl_result != 0 as HaclBnWord)
    }
}
