#![warn(missing_docs)]
//! bignum
//!
//! This module implements friendlier bignum for 4096 bit bignums
//!
//! It safely (one hopes) wraps the unsafe Hacl_Bignum operations and provides
//! a struct (type) BigUInt that should conceal the nasty pointers to mutable data.
//!
//! There are some optimizations when the big number is 1 or 0, exposing those
//! to potential side channel attacks. We are assuming that values of 1 and 0 are
//! never meant to be secrets.

use data_encoding::{HEXUPPER, HEXUPPER_PERMISSIVE};
use hacl_rust_sys::*;
use libc;
use num::{One, Zero};
use std::cmp::Ordering::{Equal, Greater, Less};
use std::fmt;
use std::ops::{Add, Mul};

// We need a feature flag for this
type HaclBnWord = u64;
// type HaclBnWord = u32;

/// A pointer to HACL_Bignum data allocated by the HACL library.
/// It typically points to 4096 bits of data, although some HACL
/// math operations will have this point to 8192 bits.
struct HaclBnHandle(HaclBnType);

impl Drop for HaclBnHandle {
    // We need to make sure that the referents are only
    // ever allocated by HaclBn... Otherwise, we will
    // panic when trying to drop these.
    // So never create a HaclBnHandle through anything other
    // then the HaclBnHandle functions.
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                libc::free(self.0 as *mut libc::c_void);
            }
        }
    }
}

impl HaclBnHandle {
    /// Has HACL create a to BN_BYTE_LENGTH bytes. This pointer can only be
    /// freed by HACL, which is called in the implementation
    /// of Drop for this structure
    ///
    /// The the referent of this pointer is expected to be filled by other HACL
    /// functions. The only guarantee on the referent is that it does not
    /// correspond to 1 or 0.
    ///
    /// # Errors
    ///
    /// - `HaclError` if HACL call returns an error condition.
    fn new() -> Result<Self, Error> {
        let mut data: [u8; BigUInt::BN_BYTE_LENGTH] = [0; BigUInt::BN_BYTE_LENGTH];
        // We don't want this to be one or zero
        data[data.len() - 1] = 255;

        let hacl_raw_bn: HaclBnType;
        unsafe {
            hacl_raw_bn =
                Hacl_Bignum4096_new_bn_from_bytes_be(data.len() as u32, data.as_mut_ptr());
        }
        if hacl_raw_bn.is_null() {
            return Err(Error::HaclError("new_bn_from_bytes".into()));
        }
        Ok(HaclBnHandle(hacl_raw_bn))
    }

    /// Has HACL create a to BN_BYTE_LENGTH bytes. This pointer can only be
    /// freed by HACL, which is called in the implementation
    /// of Drop for this structure
    ///
    /// The data pointed to is the HACL_Bignum form of the number
    /// represented by the big endian bn argument.
    ///
    /// Caller is responsible for ensuring that bn.len() <= BN_BYTE_LENGTH
    ///
    /// # Errors
    ///
    /// - `HaclError` The HACL library indicated some error. What error did it indicate? We may never know.
    fn from_vec8(bn: &[u8]) -> Result<Self, Error> {
        // Is it wasteful to allocate the the full BN_BYTE_LENGTH chunk of memory
        // if bn happens to be a lot shorter? Almost certainly. But for reasons
        // I (jpgoldberg) do not understand, I could never get this to work
        // any other way despite the fact that the Hacl_Bignum call
        // asks for the length of the data.
        let mut data: [u8; BigUInt::BN_BYTE_LENGTH] = [0; BigUInt::BN_BYTE_LENGTH];
        let diff_len = BigUInt::BN_BYTE_LENGTH - bn.len();
        data[diff_len..].copy_from_slice(bn);

        let hacl_raw_bn: HaclBnType =
            unsafe { Hacl_Bignum4096_new_bn_from_bytes_be(data.len() as u32, data.as_mut_ptr()) };

        if hacl_raw_bn.is_null() {
            return Err(Error::HaclError("new_bn_from_bytes".into()));
        }
        Ok(HaclBnHandle(hacl_raw_bn))
    }

    /// Returns the big endian vector of bytes corresponding to the value
    /// pointed to by self.
    ///
    /// # Error
    /// - `NoHandle` if self is a null pointer.
    fn to_vec8(&self) -> Result<Vec<u8>, Error> {
        let handle = self.0;
        if self.0.is_null() {
            return Err(Error::NoHandle);
        }

        let be_bytes = &mut [0_u8; BigUInt::BN_BYTE_LENGTH];
        unsafe { Hacl_Bignum4096_bn_to_bytes_be(handle, be_bytes.as_mut_ptr()) }

        Ok(be_bytes.to_vec())
    }

    /// Returns `ZeroOneOther` depending on whether the value pointed to
    /// corresponds to zero, one, or other.
    ///
    /// This is expensive. We only want to call it when the data
    /// pointed to has changed. We use this to set quicker to check flags.
    fn zero_one_other(&self) -> Result<ZeroOneOther, Error> {
        let be_vec = self.to_vec8()?;
        Ok(one_zero_other(&be_vec))
    }

    /*
    There are a number of public Hacl_Bignum functions that say that bad things will
    happen if the some of their inputs are even. But the same library does not give
    us a nice way of checking.

    The same documentation tells us not to use the internal representation of a bn, but it also tells us that the limbs are little endian. In particular

    > Furthermore, the
    > limbs are stored in little-endian format, i.e. the least significant limb is at
    > index 0. Each limb is stored in native format in memory. Example:
    >
    >   `uint64_t sixteen[64] = { 0x10 }`

    This of course will be different on 32 bit systems, but I will assume that the
    zero index'ed limb is the least significant.
    */
    /// Returns true if the value of the bn pointed to is odd.
    ///
    /// This method depends on HACL internal data layout, which we
    /// are told not to rely on. Always test this with any new update
    /// of HACL.
    fn ref_is_odd(&self) -> bool {
        let least_limb = unsafe { *(self.0.offset(0)) };
        least_limb % 2 == 1
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

// Creating a montgomery context for a Hacl bignum is extremely useful
// for those numbers that will be used as moduli.
//
// Again, we need a feature flag for 32 bit systems.
struct MontgomeryContext(*mut Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64);
// struct MontgomeryContext(*mut Hacl_Bignum_MontArithmetic_bn_mont_ctx_u32);

impl Drop for MontgomeryContext {
    fn drop(&mut self) {
        unsafe {
            Hacl_Bignum4096_mont_ctx_free(self.0);
        }
    }
}

impl MontgomeryContext {
    fn from_bn(bn_handle: &HaclBnHandle) -> Result<Self, Error> {
        let ctx = unsafe { Hacl_Bignum4096_mont_ctx_init(bn_handle.0) };

        match !ctx.is_null() {
            false => Err(Error::HaclError("mont_ctx_init".into())),
            true => Ok(Self(ctx)),
        }
    }
}

impl fmt::Debug for MontgomeryContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.0.is_null() {
            true => "is null",
            false => "isn't null",
        };
        write!(f, "Mont ctx {}.", msg)
    }
}

impl BigUInt {
    /// Attempts to create a new BigUInt with the same values.
    /// Allocates new memory with a new pointer to that memory
    pub fn try_clone(&self) -> Result<Self, Error> {
        if self.is_one() || self.is_zero() {
            return Ok(BigUInt {
                zero_one_other: self.zero_one_other,
                mont_ctx: None,
                handle: None,
            });
        }
        let old_handle = self.handle.as_ref().ok_or(Error::NoHandle)?.0;
        let be_bytes = &mut [0_u8; 512];
        unsafe { Hacl_Bignum4096_bn_to_bytes_be(old_handle, be_bytes.as_mut_ptr()) }

        BigUInt::new(be_bytes)
    }

    /// If this number is to be used as a modulus in modular arithmetic,
    /// it will be useful to have it set up a Montgomery context.
    /// This doesn't return a value if all is well, otherwise an error.
    ///
    /// This is dysfunctional in that it changes the state of self, but
    /// it doesn't change the value. And we really don't want to compute
    /// this for every bn.
    pub fn precomp_mont_ctx(&mut self) -> Result<(), Error> {
        if self.mont_ctx.is_some() {
            // cool, this has already be set up
            return Ok(());
        }
        if self.zero_one_other != ZeroOneOther::Other {
            return Err(Error::UselessModulus);
        }
        if !self.is_odd()? {
            return Err(Error::UselessModulus);
        }

        let ctx: MontgomeryContext = match &self.handle {
            None => return Err(Error::NoHandle),
            Some(h) => MontgomeryContext::from_bn(h)?,
        };

        self.mont_ctx = Some(ctx);

        Ok(())
    }

    /// (self % 2) == 1
    pub fn is_odd(&self) -> Result<bool, Error> {
        match self.zero_one_other {
            ZeroOneOther::One => Ok(true),
            ZeroOneOther::Zero => Ok(false),
            _ => match &self.handle {
                None => Err(Error::NoHandle),
                Some(h) => Ok(h.ref_is_odd()),
            },
        }
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

    /// The BigUInt is malformed, as it is neither 0, 1, nor has a handle.
    /// This should not happen.
    NoHandle,

    /// The modulus is zero or one. Don't used mod operations in such cases.
    UselessModulus,

    /// You tried to compute 0^0. That is undefined.
    ZeroToZero,

    /// HACL calls sometimes return errors on a variety of conditions.
    /// The best we can do is tell you that this happened, and provide
    /// a hint of what Hacl call produced the error.
    HaclError(String),

    /// data_encoding encountered a decoding error.
    Decoding(data_encoding::DecodeError),

    /// If I used proper logic with `match`, `if let`, and so on, we wouldn't need
    /// a ShouldNotHappen error. But here we are
    ShouldNotHappen,
}

/// BigUInt is the wrapper for the HACL (generated) C library
/// for large (up to 4096 bits) unsigned integers.
/// While it can be used for smaller unsigned integers, it
/// will be wasteful in time and memory for things substantially smaller.
///
/// ## A note on mutating moduli
///
/// BigUInt's that are to be used as moduli in modular need to be declared as
/// mutable. We do not mutate the actual value they store, but the first time
/// they are used in some operations, some pre-computations are performed that
/// we only want to compute once for each BigUInt to be used as a modulus.
/// That pre-computation is of no use for numbers that will not be used as a modulus.
///
/// ## Safety
///
/// All of the public functions safe. There is a lot of use of `unsafe` internally,
/// but what you see before you is designed to safely contain it.
/// But many functions which really should never fail are set to return Results,
/// as additional precautions.  
#[derive(Debug)]
pub struct BigUInt {
    // There does not appear to be a way to get the size of a hacl_Bignum
    // So we will keep this very unsafe pointer around.
    handle: Option<HaclBnHandle>,

    // Montgomery context handle
    mont_ctx: Option<MontgomeryContext>,

    // I am assuming that a BN of 0 or 1 is never a secret.
    zero_one_other: ZeroOneOther,
}

impl BigUInt {
    /// A BigUint representing the value 1
    pub const ONE: BigUInt = BigUInt {
        zero_one_other: ZeroOneOther::One,
        handle: None,
        mont_ctx: None,
    };

    /// A BigUint representing the value 0
    pub const ZERO: BigUInt = BigUInt {
        zero_one_other: ZeroOneOther::Zero,
        handle: None,
        mont_ctx: None,
    };

    /// The maximum number of bytes in the byte vector representation of the value
    pub const BN_BYTE_LENGTH: usize = BN_BITSIZE / 8;
}

impl PartialEq for BigUInt {
    /// self == other
    ///
    /// If the value pointed to by `self` is the same as the value pointed to by
    /// `other`, this returns true.
    ///
    /// If self or other is malformed (doesn't successfully have a numerical value)
    /// return false. (This shouldn't ever happen.)
    fn eq(&self, other: &BigUInt) -> bool {
        // first we cover all of the 1 and zero case
        // (the following code makes it look like I would have failed fizzbuzz)
        // The ones
        if self.is_one() && other.is_one() {
            return true;
        }
        if self.is_one() && !other.is_one() {
            return false;
        }
        if !self.is_one() && other.is_one() {
            return false;
        }
        // The zeros
        if self.is_zero() && other.is_zero() {
            return true;
        }
        if self.is_zero() && !other.is_zero() {
            return false;
        }
        if !self.is_zero() && other.is_zero() {
            return false;
        }

        // Now that we've dealt with all of the ones and zero cases
        // we treat comparison of anything without a handle to be false
        let a_handle = match &self.handle {
            None => return false,
            Some(x) => x.0,
        };
        if a_handle.is_null() {
            return false;
        }

        let b_handle = match &other.handle {
            None => return false,
            Some(x) => x.0,
        };
        if b_handle.is_null() {
            return false;
        }

        let hacl_result: HaclBnWord;
        unsafe {
            hacl_result = Hacl_Bignum4096_eq_mask(a_handle, b_handle);
        }
        hacl_result != 0 as HaclBnWord
    }
}

// Some Vec<u8> utilities

const VEC_ONE: [u8; 1] = [1_u8];
const VEC_ZERO: [u8; 1] = [0_u8];

// This could be done for any Vec<T>
// with second argument that is T -> bool,
// but let me just do this the very concrete way.
fn trim_left_zero(v: &[u8]) -> Vec<u8> {
    let result: Vec<u8> = v.iter().copied().skip_while(|x| *x == 0_u8).collect();

    if result.is_empty() {
        VEC_ZERO.to_vec()
    } else {
        result
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

impl BigUInt {
    /// creates a new BigUint from an array of bytes.
    ///
    /// # Errors
    ///
    /// - `BadInputLength`: Length of input exceeds `BN_BYTE_LENGTH`
    /// - `HaclError`: Something went wrong with the internal call to the
    ///     HACL library. Probably a memory allocation error.
    pub fn new(be_bytes: &[u8]) -> Result<Self, Error> {
        if be_bytes.len() > BigUInt::BN_BYTE_LENGTH {
            return Err(Error::BadInputLength);
        }
        match one_zero_other(&trim_left_zero(be_bytes)) {
            ZeroOneOther::One => Ok(BigUInt::ONE),
            ZeroOneOther::Zero => Ok(BigUInt::ZERO),
            ZeroOneOther::Other => {
                let handle = HaclBnHandle::from_vec8(be_bytes)?;
                Ok(Self {
                    zero_one_other: ZeroOneOther::Other,
                    handle: Some(handle),
                    mont_ctx: None,
                })
            }
        }
    }

    /// returns a vector of big-endian bytes.
    ///
    /// # Errors
    ///
    /// - `NoHandle`. Somehow or other self never got its HACL bn pointer set up.
    /// - `HaclError`. The call to the HACL function returned an unspecified error. Probably memory allocation problem.
    pub fn to_vec8(&self) -> Result<Vec<u8>, Error> {
        match self.zero_one_other {
            ZeroOneOther::One => Ok(VEC_ONE.to_vec()),
            ZeroOneOther::Zero => Ok(VEC_ZERO.to_vec()),
            ZeroOneOther::Other => {
                // The handle better be good if we aren't zero or one
                let handle = self.handle.as_ref().ok_or(Error::NoHandle)?;
                handle.to_vec8()
            }
        }
    }

    /// A hex representation of the big-endian representation
    pub fn to_hex(&self) -> String {
        let mut be_bytes = if let Ok(v) = self.to_vec8() {
            trim_left_zero(&v)
        } else {
            return "".to_string();
        };

        if be_bytes.len() % 2 == 1 {
            // There are probably better ways to do this.
            be_bytes.insert(0, 0_u8);
        }
        // that can sometimes leave us with two zero bytes at the beginning

        let tmp_hex = HEXUPPER.encode(&be_bytes);
        let s = tmp_hex.as_str();
        match s.strip_prefix("00") {
            None => s.to_string(),
            Some(x) => x.to_string(),
        }
    }
    /// From a hex string
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let be_bytes = HEXUPPER_PERMISSIVE
            .decode(s.as_bytes())
            .map_err(Error::Decoding)?;
        Self::new(&be_bytes)
    }
}

// Can't implement One and Zero until Addition and Multiplication are implemented.
// impl num::One for BigUInt {
impl BigUInt {
    /// Returns true if our BigUInt is 1. False otherwise.
    fn is_one(&self) -> bool {
        self.zero_one_other == ZeroOneOther::One
    }
    /// returns a BigUInt representing the value 1.
    fn one() -> Self {
        BigUInt::ONE
    }
}

// impl num::Zero for BigUInt {
impl BigUInt {
    /// Returns true if our BigUInt is 0. False otherwise.
    fn is_zero(&self) -> bool {
        self.zero_one_other == ZeroOneOther::Zero
    }
    // returns a BigUInt representing the value 0.
    fn zero() -> Self {
        BigUInt::ZERO
    }
}

/* coming soon
impl Add<&BigUInt> for BigUInt {

}
*/

impl PartialOrd for BigUInt {
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
impl BigUInt {
    // We will try to use the same function signatures as exist in
    // num-bigint::BigUint, except that we will wrap in Results where
    // num-bigint panics
    // https://docs.rs/num-bigint/latest/num_bigint/struct.BigUint.html

    pub fn modpow(&self, exponent: &Self, modulus: &mut Self) -> Result<Self, Error> {
        //! Returns (self ^ exponent) % modulus.
        //!
        //! `modulus` must be mutable to allow for some precomputation on itself.
        //! The actual value it points to is not changed.
        //!
        //! # Errors
        //! - Error if modulus < 2.
        //! - Error if both self and exponent are zero.
        //! - Error if
        //!     * modulus is even
        //!     * self is not less than modulus
        //!
        //! # Security
        //!
        //! This is a constant time operation
        //! designed to avoid side-channel attacks,
        //! but it does reveal timing information if the  base or exponent
        //! are 1 or 0.
        //!
        //! We are assuming that a value of 1 or 0 is never a secret for a BigUInt.

        if self.is_zero() && exponent.is_zero() {
            return Err(Error::ZeroToZero);
        }
        if modulus.is_zero() || modulus.is_one() {
            return Err(Error::UselessModulus);
        }

        if self.is_zero() {
            return Ok(BigUInt::ZERO);
        }
        if self.is_one() {
            return Ok(BigUInt::ONE);
        }
        if exponent.is_zero() {
            return Ok(BigUInt::ONE);
        }
        if exponent.is_one() {
            return self.try_clone();
        }

        // We should now be in a state in which we know that base and exponent
        // are greater than 1, so we need call Hacl_Bignum4096_mod_exp_consttime

        // let's get the Hacl parameters (and with the names used by HACL)
        // a^b mod n into res or a^b montgomery_mod k into res
        let a = self.handle.as_ref().ok_or(Error::NoHandle)?.0;
        let b = exponent.handle.as_ref().ok_or(Error::NoHandle)?.0;

        // I still can't find a way to get the size of Hacl bignnums, so will
        // just use the maximum
        #[allow(non_snake_case)]
        let bBits = 8 * Self::BN_BYTE_LENGTH;

        let handle = HaclBnHandle::new()?;

        // The computation to create the Montgomery form of the modulus is
        // going to be done even if we use Hacl_Bignum4096_mod_exp_consttime
        // but we won't get to keep that around unless we explicitly compute it.
        //
        if modulus.mont_ctx.is_none() {
            modulus.precomp_mont_ctx()?;
        }

        let k = modulus.mont_ctx.as_ref().ok_or(Error::ShouldNotHappen)?.0;
        unsafe {
            Hacl_Bignum4096_mod_exp_consttime_precomp(k, a, bBits as u32, b, handle.0);
        }

        let zero_one_other = handle.zero_one_other()?;

        Ok(Self {
            zero_one_other,
            handle: Some(handle),
            mont_ctx: None,
        })
    }

    /// num % self
    ///
    /// `self` is mutable to allow for some precomputation that should only
    /// be done once for anything used as a modulus.
    ///
    /// # Errors
    /// - `UselessModulus` if self < 2 or if self is even.
    /// - `HaclError` if something some Hacl call returned an error
    ///
    pub fn mod_reduce(&mut self, num: &Self) -> Result<Self, Error> {
        if self.mont_ctx.is_none() {
            self.precomp_mont_ctx()?;
        }

        let handle = HaclBnHandle::new()?;

        let a = num.handle.as_ref().ok_or(Error::NoHandle)?.0;
        let k = self.mont_ctx.as_ref().ok_or(Error::ShouldNotHappen)?.0;
        unsafe {
            Hacl_Bignum4096_mod_precomp(k, a, handle.0);
        }

        let zero_one_other = handle.zero_one_other()?;
        Ok(Self {
            zero_one_other,
            handle: Some(handle),
            mont_ctx: None,
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
