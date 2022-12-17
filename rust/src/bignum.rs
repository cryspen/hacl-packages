#![warn(missing_docs)]
//! bignum
//!
//! This module implements friendlier bignum for 4096 bit bignums
//!
//! It safely (one hopes) wraps the unsafe Hacl_Bignum operations and provides
//! structs (types) [BigUInt] and [Modulus] that should conceal the nasty
//! C allocated pointers to mutable data.
//!
//! There are some optimizations when the big number is 1 or 0, exposing those
//! to side channel attacks. We are assuming that values of 1 and 0 are
//! never meant to be secrets.

use data_encoding::{HEXUPPER, HEXUPPER_PERMISSIVE};
use hacl_rust_sys::*;
use libc;
use std::cmp::Ordering::{Equal, Greater, Less};
use std::fmt;
use std::mem;

// We need a feature flag for this
type HaclBnWord = u64;
// type HaclBnWord = u32;

/// A pointer to HACL_Bignum data allocated by the HACL library.
/// It typically points to 4096 bits of data, although some HACL
/// math operations will have this point to 8192 bits.
struct HaclBnHandle {
    ptr: HaclBnType,
    bitsize: usize,
}

impl Drop for HaclBnHandle {
    // We need to make sure that the referents are only
    // ever allocated by HaclBn... Otherwise, we will
    // panic when trying to drop these.
    // So never create a HaclBnHandle through anything other
    // then the HaclBnHandle functions.
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                libc::free(self.ptr as *mut libc::c_void);
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
    /// functions.
    ///
    /// # Errors
    ///
    /// - `HaclError` if HACL call returns an error condition.
    fn new(bitsize: usize) -> Result<Self, Error> {
        // bad things happen if bitsize is not a multiple of the 64 (or perhaps 4096)
        if bitsize % 64 != 0 {
            return Err(Error::BadInputLength);
        }
        let byte_length = 8 * bitsize;

        let mut data_vec = vec![255_u8; byte_length];
        data_vec.shrink_to_fit();
        let data_ptr = data_vec.as_mut_ptr();

        let hacl_raw_bn: HaclBnType;
        unsafe {
            hacl_raw_bn = Hacl_Bignum4096_new_bn_from_bytes_be(byte_length as u32, data_ptr);
        }
        if hacl_raw_bn.is_null() {
            return Err(Error::HaclError("new_bn_from_bytes".into()));
        }
        Ok(HaclBnHandle {
            ptr: hacl_raw_bn,
            bitsize,
        })
    }

    // Some HACL 4096 bit arithmetic wants arguments to be 8192 bits.
    fn supersize(&self) -> Result<Self, Error> {
        let bitsize = 2 * BN_BITSIZE;
        let byte_length = bitsize / 8;

        let mut data: [u8; 2 * BigUInt::BN_BYTE_LENGTH] = [0; 2 * BigUInt::BN_BYTE_LENGTH];
        let old_vec = &self.to_vec8()?;
        let diff_len = 2 * BigUInt::BN_BYTE_LENGTH - old_vec.len();
        data[diff_len..].copy_from_slice(old_vec);
        let data_ptr = data.as_mut_ptr();

        let hacl_raw_bn: HaclBnType;
        unsafe {
            hacl_raw_bn = Hacl_Bignum4096_new_bn_from_bytes_be(byte_length as u32, data_ptr);
        }
        if hacl_raw_bn.is_null() {
            return Err(Error::HaclError("new_bn_from_bytes".into()));
        }
        Ok(HaclBnHandle {
            ptr: hacl_raw_bn,
            bitsize,
        })
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
        Ok(HaclBnHandle {
            ptr: hacl_raw_bn,
            bitsize: BN_BITSIZE,
        })
    }

    /// Returns the big endian vector of bytes corresponding to the value
    /// pointed to by self.
    ///
    /// # Error
    /// - `NoHandle` if self is a null pointer.
    fn to_vec8(&self) -> Result<Vec<u8>, Error> {
        if self.ptr.is_null() {
            return Err(Error::NoHandle);
        }

        let be_bytes = &mut [0_u8; BigUInt::BN_BYTE_LENGTH];
        unsafe {
            let b = self.mut_ptr();
            Hacl_Bignum4096_bn_to_bytes_be(b, be_bytes.as_mut_ptr())
        }

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

    This of course will be different type on 32 bit systems,
    but I expect that the logic should still apply and that the
    zero index'ed limb is the least significant.
    */
    /// Returns true if the value of the bn pointed to is odd.
    ///
    /// This method depends on HACL internal data layout, which we
    /// are told not to rely on. Always test this with any new update
    /// of HACL.
    fn ref_is_odd(&self) -> bool {
        let least_limb = unsafe { *(self.ptr.offset(0)) };
        least_limb % 2 == 1
    }

    // lots of unsafe stuff
    unsafe fn mut_ptr(&self) -> *mut HaclBnWord {
        mem::transmute_copy(&self.ptr)
    }
}

impl fmt::Debug for HaclBnHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.ptr.is_null() {
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
        if !self.0.is_null() {
            unsafe {
                Hacl_Bignum4096_mont_ctx_free(self.0);
            }
        }
    }
}

impl MontgomeryContext {
    fn from_bn(bn_handle: &HaclBnHandle) -> Result<Self, Error> {
        let ctx = unsafe {
            let n = bn_handle.mut_ptr();
            Hacl_Bignum4096_mont_ctx_init(n)
        };

        match !ctx.is_null() {
            false => Err(Error::HaclError("mont_ctx_init".into())),
            true => Ok(Self(ctx)),
        }
    }
}

// Montgomery context is never mutated after creation.

unsafe impl Sync for MontgomeryContext {}

// BigUInt and Modulus won't ever be mutated after creation,
// but I need to tell this as a lie so that I can create the statics
// that allow me to do away with the mutation.
unsafe impl Sync for BigUInt {}
unsafe impl Sync for Bui {}

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
    /// Takes ownership of self and returns a Modulus built from it.
    pub fn into_modulus(mut self) -> Result<Modulus, Error> {
        if self.0.zero_one_other != ZeroOneOther::Other {
            Err(Error::BadModulus(ModulusError::LessThanTwo))
        } else if self.is_even()? {
            Err(Error::BadModulus(ModulusError::Even))
        } else if self.is_supersize() {
            Err(Error::BadModulus(ModulusError::TooLarge))
        } else {
            self.precomp_mont_ctx()?;

            let zero_one_other = ZeroOneOther::Other;

            // Danger, danger, Will Robinson!
            let mut sh = self.0.handle.ok_or(Error::NoHandle)?;

            // Copy may not be implemented for HaclBnHandle, so we do this manually
            let h = HaclBnHandle {
                ptr: sh.ptr,
                bitsize: sh.bitsize,
            };

            // We set self's handle to a null pointer so that when
            // self drops it doesn't free the memory pointed to
            // by the new Modulus's handle
            sh.ptr = std::ptr::null_mut::<HaclBnWord>();

            let mut mc = self.0.mont_ctx.ok_or(Error::ShouldNotHappen)?;
            let mont_ctx = MontgomeryContext(mc.0);
            // And now the same stunt with the Montgomery context
            mc.0 = std::ptr::null_mut();

            Ok(Modulus(Bui {
                zero_one_other,
                handle: Some(h),
                mont_ctx: Some(mont_ctx),
            }))
        }
    }

    /// Attempts to create a new BigUInt with the same values.
    /// Allocates new memory with a new pointer to that memory
    pub fn try_clone(&self) -> Result<Self, Error> {
        if self.is_one() || self.is_zero() {
            return Ok(BigUInt(Bui {
                zero_one_other: self.0.zero_one_other,
                mont_ctx: None,
                handle: None,
            }));
        }
        let old_handle = self.0.handle.as_ref().ok_or(Error::NoHandle)?;
        let be_bytes = &mut [0_u8; 512];
        unsafe {
            let b = old_handle.mut_ptr();
            Hacl_Bignum4096_bn_to_bytes_be(b, be_bytes.as_mut_ptr())
        }

        BigUInt::from_bytes_be(be_bytes)
    }

    /// If this number is to be used as a modulus in modular arithmetic,
    /// it will be useful to have it set up a Montgomery context.
    /// This doesn't a value if all is well, otherwise an error.
    ///
    /// This is dysfunctional in that it changes the state of self,
    /// but the [mutability](#mutability) doesn't change the value
    /// represented; it merely performs some pre-computation if necessary
    ///
    /// # Errors
    /// - [Error::BadModulus]: The modulus is either < 2 or is even.
    /// - [Error::HaclError]: Something went wrong at a deeper level.
    ///
    pub fn precomp_mont_ctx(&mut self) -> Result<(), Error> {
        self.0.precomp_mont_ctx()
    }

    fn is_supersize(&self) -> bool {
        match &self.0.handle {
            None => false,
            Some(h) => h.bitsize > BN_BITSIZE,
        }
    }

    fn supersize(&self) -> Result<Self, Error> {
        // TODO: handle cases where self is 0 or 1 and has not handle
        let zero_one_other = self.0.zero_one_other;
        let handle = self
            .0
            .handle
            .as_ref()
            .expect("supersize: cannot happen")
            .supersize()?;

        Ok(Self(Bui {
            zero_one_other,
            handle: Some(handle),
            mont_ctx: None,
        }))
    }
}

/// HaclBnType is used in unsafe operations
type HaclBnType = *const HaclBnWord;

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

    /// The modulus must be an odd number in (3..2^4096 -1)
    BadModulus(ModulusError),

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

/// How can a modulus be bad. Let me count the ways.
#[derive(Debug, PartialEq)]
pub enum ModulusError {
    /// Is 1 or 0
    LessThanTwo,

    /// We can't cope with even moduli for our math
    Even,

    /// A modulus must be less than [BigUint::BN_BITSIZE] bits.
    TooLarge,
}

/// BigUInt is the wrapper for the HACL (generated) C library
/// for large (up to 4096 bits) unsigned integers.
/// While it can be used for smaller unsigned integers, it
/// will be wasteful in time and memory for things substantially smaller.
///
/// ## <a name="mutability"></a>A note on functional mutability
///
/// Many of the methods call for mutable BigUInts.
/// These do not change the actual value represented,
/// but instead allow for some internal pre-computation.
///
/// For example, numbers used as moduli need a certain precomputation
/// that will fail for even numbers and for 1.
/// So it is very useful to selectively perform that precomputation.
/// There are other precomputation (or memory allocations) that are
/// selectively applied to other numbers.
///
/// ## Safety
///
/// All of the public functions safe. There is a lot of use of `unsafe` internally,
/// but what you see before you is designed to safely contain it.
/// But many functions which really should never fail are set to return Results,
/// as additional precautions.
///
/// [mutability]: #a-note-on-functional-mutability
pub struct BigUInt(Bui);

/// A modulus is a [BigUInt] that is to be used as a modulus for
/// modular arithmetic.
pub struct Modulus(Bui);

#[derive(Debug)]
struct Bui {
    // There does not appear to be a way to get the size of a hacl_Bignum
    // So we will keep this very unsafe pointer around.
    handle: Option<HaclBnHandle>,

    // Montgomery context handle
    mont_ctx: Option<MontgomeryContext>,

    // I am assuming that a BN of 0 or 1 is never a secret.
    zero_one_other: ZeroOneOther,
}

lazy_static! {
    /// A static bigUInt with the value 1
    pub static ref ONE: BigUInt =
        BigUInt::from_bytes_be(&[1_u8]).expect("static creation of ONE failed");

   /// A static bigUInt with value 0
    pub static ref ZERO: BigUInt =
        BigUInt::from_bytes_be(&[0_u8]).expect("static creation of ZERO failed");
}

impl Bui {
    fn is_one(&self) -> bool {
        match self.zero_one_other {
            ZeroOneOther::One => true,
            ZeroOneOther::Zero => false,
            ZeroOneOther::Other => self.eq(&ONE.0),
        }
    }
    fn is_zero(&self) -> bool {
        match self.zero_one_other {
            ZeroOneOther::One => false,
            ZeroOneOther::Zero => true,
            ZeroOneOther::Other => self.eq(&ZERO.0),
        }
    }

    fn to_vec8(&self) -> Result<Vec<u8>, Error> {
        self.handle.as_ref().expect("shouldn't happen").to_vec8()
    }

    fn from_bytes_be(be_bytes: &[u8]) -> Result<Self, Error> {
        if be_bytes.len() > BigUInt::BN_BYTE_LENGTH {
            return Err(Error::BadInputLength);
        }

        let handle = HaclBnHandle::from_vec8(be_bytes)?;
        Ok(Bui {
            zero_one_other: ZeroOneOther::Other,
            handle: Some(handle),
            mont_ctx: None,
        })
    }

    fn to_hex(&self) -> String {
        if self.zero_one_other == ZeroOneOther::One {
            return "01".to_string();
        } else if self.zero_one_other == ZeroOneOther::Zero {
            return "00".to_string();
        }
        let mut be_bytes = if let Ok(v) = self.to_vec8() {
            trimmed_left(&v)
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

    fn from_hex(s: &str) -> Result<Self, Error> {
        let be_bytes = HEXUPPER_PERMISSIVE
            .decode(s.as_bytes())
            .map_err(Error::Decoding)?;
        Self::from_bytes_be(&be_bytes)
    }

    /// (self % 2) == 1
    fn is_odd(&self) -> Result<bool, Error> {
        match self.zero_one_other {
            ZeroOneOther::One => Ok(true),
            ZeroOneOther::Zero => Ok(false),
            _ => match &self.handle {
                None => Err(Error::NoHandle),
                Some(h) => Ok(h.ref_is_odd()),
            },
        }
    }

    // I am guessing that the compiler knows better than I do whether to inline this.
    fn is_even(&self) -> Result<bool, Error> {
        match Bui::is_odd(self) {
            Err(e) => Err(e),
            Ok(b) => Ok(!b),
        }
    }

    fn precomp_mont_ctx(&mut self) -> Result<(), Error> {
        if self.mont_ctx.is_some() {
            // cool, this has already be set up
            return Ok(());
        }
        if self.is_one() || self.is_zero() {
            return Err(Error::BadModulus(ModulusError::LessThanTwo));
        }
        if self.is_even()? {
            return Err(Error::BadModulus(ModulusError::Even));
        }

        let ctx: MontgomeryContext = match &self.handle {
            None => return Err(Error::NoHandle),
            Some(h) => MontgomeryContext::from_bn(h)?,
        };

        self.mont_ctx = Some(ctx);

        Ok(())
    }

    fn bitsize(&self) -> usize {
        if self.zero_one_other != ZeroOneOther::Other {
            8_usize
        } else {
            let h = self.handle.as_ref().expect("Shouldn't happen");
            h.bitsize
        }
    }
}

impl PartialEq for Bui {
    //! Implements [PartialEq] for [BigUInt]

    /// self == other
    ///
    /// If the value pointed to by `self` is the same as the value pointed to by
    /// `other`, this returns true.
    ///
    /// If self or other is malformed (doesn't successfully have a numerical value)
    /// return false. (This shouldn't ever happen.)
    fn eq(&self, other: &Bui) -> bool {
        // The cases where either self or other announce themselves
        // to be 1 or 0 gets tricky because a listing as Other may
        // be incorrect.
        let s_zoo = self.zero_one_other;
        let o_zoo: ZeroOneOther = other.zero_one_other;
        if s_zoo != ZeroOneOther::Other && o_zoo != ZeroOneOther::Other {
            return s_zoo == o_zoo;
        }
        if s_zoo == ZeroOneOther::One {
            return other.is_one();
        }
        if s_zoo == ZeroOneOther::Zero {
            return other.is_zero();
        }
        if o_zoo == ZeroOneOther::One {
            return self.is_one();
        }
        if o_zoo == ZeroOneOther::Zero {
            return self.is_zero();
        }

        // both list as Other (still may be zero or one), but they
        // have handles for proper comparison
        let a_handle = match &self.handle {
            None => return false,
            Some(x) => x,
        };
        if a_handle.ptr.is_null() {
            return false;
        }

        let b_handle = match &other.handle {
            None => return false,
            Some(x) => x,
        };
        if b_handle.ptr.is_null() {
            return false;
        }

        let hacl_result: HaclBnWord;
        unsafe {
            let a = a_handle.mut_ptr();
            let b = b_handle.mut_ptr();
            hacl_result = Hacl_Bignum4096_eq_mask(a, b);
        }
        hacl_result != 0 as HaclBnWord
    }
}

impl PartialOrd for Bui {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if (self.is_one() && other.is_one()) || (self.is_zero() && other.is_zero()) {
            return Some(Equal);
        }
        let a_handle = match &self.handle {
            None => return None, // really shouldn't happen
            Some(h) => h,
        };
        let b_handle = match &other.handle {
            None => return None, // really shouldn't happen
            Some(h) => h,
        };

        // We do not know how to compare the 8192 bit things.
        if self.bitsize() > BN_BITSIZE || other.bitsize() > BN_BITSIZE {
            return None;
        }

        let lt_result: HaclBnWord;
        let eq_result: HaclBnWord;
        unsafe {
            let a = a_handle.mut_ptr();
            let b = b_handle.mut_ptr();
            lt_result = Hacl_Bignum4096_lt_mask(a, b);
            eq_result = Hacl_Bignum4096_eq_mask(a, b);
        }
        if eq_result != 0 as HaclBnWord {
            return Some(Equal);
        } else if lt_result == 0 as HaclBnWord {
            return Some(Greater);
        }
        Some(Less)
    }
}

/// What every BigUInt needs
pub trait BigUnsigned {
    /// creates a [BigUInt] from a slice of bytes representing
    /// value in big-endian order.
    fn from_bytes_be(_: &[u8]) -> Result<Self, Error>
    where
        Self: std::marker::Sized;

    /// returns a vector of big-endian bytes
    fn to_vec8(&self) -> Result<Vec<u8>, Error>;

    /// An uppercase hex representation of the big-endian representation
    /// of the value of `self`.
    ///
    /// Output is an uppercase string representing a whole number of bytes,
    /// but does not include a leading 0 bytes.
    /// For example a value equivalent to decimal 3053 will yield `0BED`.
    /// A value of zero will yield `00`.
    fn to_hex(&self) -> String;

    /// The argument is upper case hex [str]
    /// complying with [data_encoding::HEXUPPER_PERMISSIVE]
    /// which represents a big-endian sequence of bytes.
    fn from_hex(s: &str) -> Result<Self, Error>
    where
        Self: std::marker::Sized;
}

impl BigUnsigned for Modulus {
    fn from_bytes_be(be_bytes: &[u8]) -> Result<Self, Error> {
        // we can't just call BigUInt::from_bytes_be to create a
        // temporary bn because when that gets dropped bad
        // the memory pointed to by the handle is freed.
        match one_zero_other(be_bytes) {
            ZeroOneOther::Other => {
                let mut bui = Bui::from_bytes_be(be_bytes)?;
                bui.precomp_mont_ctx()?;
                Ok(Self(bui))
            }
            _ => Err(Error::BadModulus(ModulusError::LessThanTwo)),
        }
    }

    fn to_vec8(&self) -> Result<Vec<u8>, Error> {
        self.0.to_vec8()
    }

    /// An uppercase hex representation of the big-endian representation
    /// of the value of `self`.
    ///
    /// Output is an uppercase string representing a whole number of bytes,
    /// but does not include a leading 0 bytes.
    /// For example a value equivalent to decimal 3053 will yield `0BED`.
    /// A value of zero will yield `00`.
    fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// The argument is upper case hex [str]
    /// complying with [data_encoding::HEXUPPER_PERMISSIVE]
    /// which represents a big-endian sequence of bytes.
    fn from_hex(s: &str) -> Result<Self, Error> {
        let mut bui = Bui::from_hex(s)?;
        bui.precomp_mont_ctx()?;
        Ok(Self(bui))
    }
}

impl BigUnsigned for BigUInt {
    fn from_hex(s: &str) -> Result<Self, Error> {
        let bui = Bui::from_hex(s)?;
        Ok(Self(bui))
    }

    fn from_bytes_be(be_bytes: &[u8]) -> Result<Self, Error> {
        let bui = Bui::from_bytes_be(be_bytes)?;
        Ok(Self(bui))
    }

    fn to_vec8(&self) -> Result<Vec<u8>, Error> {
        self.0.to_vec8()
    }

    fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl Modulus {
    /// `number % self`
    pub fn reduce(&self, number: &BigUInt) -> Result<BigUInt, Error> {
        if number.is_one() {
            return Ok(BigUInt::ONE);
        }
        if number.is_zero() {
            return Ok(BigUInt::ZERO);
        }
        number.0.handle.as_ref().ok_or(Error::NoHandle)?;

        let a = &number.supersize()?;

        let handle = HaclBnHandle::new(BN_BITSIZE)?;

        let ah = a.0.handle.as_ref().ok_or(Error::NoHandle)?;
        let k = self.0.mont_ctx.as_ref().ok_or(Error::ShouldNotHappen)?.0;
        unsafe {
            let a = ah.mut_ptr();
            let res = handle.mut_ptr();
            Hacl_Bignum4096_mod_precomp(k, a, res);
        }

        let zero_one_other = handle.zero_one_other()?;
        Ok(BigUInt(Bui {
            zero_one_other,
            handle: Some(handle),
            mont_ctx: None,
        }))
    }

    /// Creates a new [Modulus] from a [BigUInt]
    ///
    /// # Errors
    ///
    /// - [Error::BadModulus] if argument is < 2, is even, or is supersized.
    /// - Any variety of [Error::HaclError] or other errors that can arise from trying to allocate a new [BigUnsigned].
    pub fn from_biguint(src_bn: &BigUInt) -> Result<Self, Error> {
        if src_bn.0.zero_one_other != ZeroOneOther::Other {
            return Err(Error::BadModulus(ModulusError::LessThanTwo));
        }
        if src_bn.0.handle.is_none() {
            return Err(Error::ShouldNotHappen);
        }
        if src_bn.is_even()? {
            return Err(Error::BadModulus(ModulusError::Even));
        }
        if src_bn.is_supersize() {
            return Err(Error::BadModulus(ModulusError::TooLarge));
        }

        // Sadly we have to re-allocate the same data to be able
        // to use the safety we get from dropping.
        let mut bn = src_bn.try_clone()?;
        bn.precomp_mont_ctx()?;

        Ok(Self(bn.0))
    }

    /// (a + b) % self
    pub fn add(self, a: &BigUInt, b: &BigUInt) -> Result<BigUInt, Error> {
        if a.is_zero() {
            return b.try_clone();
        }
        if b.is_zero() {
            return a.try_clone();
        }
        // HACL notes say the caller is responsible for ensuring
        // that a < n and b < n.
        // This is where we take on our responsibility
        let a = self.reduce(a)?;
        let b = self.reduce(b)?;

        let result_handle = HaclBnHandle::new(BN_BITSIZE)?;

        let ah = a.0.handle.as_ref().ok_or(Error::ShouldNotHappen)?;
        let bh = b.0.handle.as_ref().ok_or(Error::ShouldNotHappen)?;
        let nh = self.0.handle.as_ref().ok_or(Error::ShouldNotHappen)?;

        unsafe {
            let a = ah.mut_ptr();
            let b = bh.mut_ptr();
            let n = nh.mut_ptr();
            let res = result_handle.mut_ptr();
            Hacl_Bignum4096_add_mod(n, a, b, res)
        }
        let zero_one_other = result_handle.zero_one_other()?;

        Ok(BigUInt(Bui {
            zero_one_other,
            handle: Some(result_handle),
            mont_ctx: None,
        }))
    }
}

impl BigUInt {
    //! Constants

    /// A BigUint representing the value 1
    pub const ONE: BigUInt = BigUInt(Bui {
        zero_one_other: ZeroOneOther::One,
        handle: None,
        mont_ctx: None,
    });

    /// A BigUint representing the value 0
    pub const ZERO: BigUInt = BigUInt(Bui {
        zero_one_other: ZeroOneOther::Zero,
        handle: None,
        mont_ctx: None,
    });

    /// The maximum number of bytes in the byte vector representation of the value
    pub const BN_BYTE_LENGTH: usize = BN_BITSIZE / 8;
}

impl PartialEq for BigUInt {
    //! Implements [PartialEq] for [BigUInt]

    /// self == other
    ///
    /// If the value pointed to by `self` is the same as the value pointed to by
    /// `other`, this returns true.
    ///
    /// If self or other is malformed (doesn't successfully have a numerical value)
    /// return false. (This shouldn't ever happen.)
    fn eq(&self, other: &BigUInt) -> bool {
        self.0.eq(&other.0)
    }
}

impl PartialEq<Modulus> for BigUInt {
    fn eq(&self, other: &Modulus) -> bool {
        self.0.eq(&other.0)
    }
}

impl PartialEq for Modulus {
    //! Implements [PartialEq] for [BigUInt]

    /// self == other
    ///
    /// If the value pointed to by `self` is the same as the value pointed to by
    /// `other`, this returns true.
    ///
    /// If self or other is malformed (doesn't successfully have a numerical value)
    /// return false. (This shouldn't ever happen.)
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl PartialEq<BigUInt> for Modulus {
    fn eq(&self, other: &BigUInt) -> bool {
        self.0.eq(&other.0)
    }
}

// There is probably a generic way or a macro_rules! way to get the following
// four implementations into one thing. But I am not going to figure that out today.
impl PartialOrd for BigUInt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
impl PartialOrd<Modulus> for BigUInt {
    fn partial_cmp(&self, other: &Modulus) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
impl PartialOrd for Modulus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
impl PartialOrd<BigUInt> for Modulus {
    fn partial_cmp(&self, other: &BigUInt) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

// Some Vec<u8> utilities

const VEC_ONE: [u8; 1] = [1_u8];
const VEC_ZERO: [u8; 1] = [0_u8];

// This could be done for any Vec<T>
// with second argument that is T -> bool,
// but let me just do this the very concrete way.
fn trimmed_left(v: &[u8]) -> Vec<u8> {
    let result: Vec<u8> = v.iter().copied().skip_while(|x| *x == 0_u8).collect();

    if result.is_empty() {
        VEC_ZERO.to_vec()
    } else {
        result
    }
}

fn one_zero_other(v: &[u8]) -> ZeroOneOther {
    let b = trimmed_left(v);
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
    //! Functions and methods for creating [BigUInt]
    //! and methods for exporting their values in other formats.
    //!
    //! Functions [one][BigUInt::one] and [zero][BigUInt::zero]
    //! for creating [BigUInt]s of value 0 or 1
    //! are listed in a different section.

    /// creates a new BigUint from an array of bytes.
    ///
    /// # Errors
    ///
    /// - [Error::BadInputLength]: Length of input exceeds [BigUInt::BN_BYTE_LENGTH]
    /// - [Error::HaclError]: Something went wrong with the internal call to the
    ///     HACL library. Probably a memory allocation error.
    pub fn from_bytes_be(be_bytes: &[u8]) -> Result<Self, Error> {
        let bui = Bui::from_bytes_be(be_bytes)?;
        Ok(Self(bui))
    }

    /// returns a vector of big-endian bytes.
    ///
    /// # Errors
    ///
    /// - `NoHandle`. Somehow or other self never got its HACL bn pointer set up.
    /// - `HaclError`. The call to the HACL function returned an unspecified error. Probably memory allocation problem.
    pub fn to_vec8(&self) -> Result<Vec<u8>, Error> {
        match self.0.zero_one_other {
            ZeroOneOther::One => Ok(VEC_ONE.to_vec()),
            ZeroOneOther::Zero => Ok(VEC_ZERO.to_vec()),
            ZeroOneOther::Other => {
                // The handle better be good if we aren't zero or one
                let handle = self.0.handle.as_ref().ok_or(Error::NoHandle)?;
                handle.to_vec8()
            }
        }
    }

    /// An uppercase hex representation of the big-endian representation
    /// of the value of `self`.
    ///
    /// Output is an uppercase string representing a whole number of bytes,
    /// but does not include a leading 0 bytes.
    /// For example a value equivalent to decimal 3053 will yield `0BED`.
    /// A value of zero will yield `00`.
    ///
    /// # Errors
    ///
    /// This method does not return errors,
    /// but if things which shouldn't happen happen it will return an empty string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// if self is zero or one with no allocated Hacl BN handle, this will
    /// allocate a Hacl Bignum 1 or 0.
    ///
    /// # Errors
    ///
    /// - Passes errors from [HaclBnHandle::from_vec8()]
    /// - [Error::NoHandle] if not 0 or 1 and there is no handle in place.
    #[allow(dead_code)]
    fn ensure_handle(&mut self) -> Result<(), Error> {
        if self.0.handle.is_some() {
            return Ok(());
        }
        match self.0.zero_one_other {
            ZeroOneOther::One => {
                self.0.handle = Some(HaclBnHandle::from_vec8(&VEC_ONE)?);
                Ok(())
            }
            ZeroOneOther::Zero => {
                self.0.handle = Some(HaclBnHandle::from_vec8(&VEC_ZERO)?);
                Ok(())
            }
            ZeroOneOther::Other => Err(Error::NoHandle),
        }
    }
}

/// Incomplete implementation of `num::traits::One`
impl BigUInt {
    /// Returns true if our BigUInt is 1. False otherwise.
    pub fn is_one(&self) -> bool {
        self.0.eq(&ONE.0)
    }
    /// returns a BigUInt representing the value 1.
    pub fn one() -> Self {
        BigUInt::ONE
    }
}

/// Incomplete implementation of `num::traits::One`
impl BigUInt {
    /// Returns true if our BigUInt is 0. False otherwise.
    pub fn is_zero(&self) -> bool {
        self.0.eq(&ZERO.0)
    }

    /// Returns true if self is 1. False otherwise.
    pub fn zero() -> Self {
        BigUInt::ZERO
    }
}

/// Arithmetic methods
impl BigUInt {
    // We will try to use the same function signatures as exist in
    // num-bigint::BigUint, except that we will wrap in Results where
    // num-bigint panics
    // https://docs.rs/num-bigint/latest/num_bigint/struct.BigUint.html

    /// (self % 2) == 1
    pub fn is_odd(&self) -> Result<bool, Error> {
        self.0.is_odd()
    }
    /// (self % 2) == 0
    pub fn is_even(&self) -> Result<bool, Error> {
        self.0.is_even()
    }

    /// `(a + b) % self`.
    ///
    /// The modulus (`self`) must not be even and must not be 1.
    ///
    /// The [mutability](#mutability) doesn't change the numeric values
    /// but is needed for some
    /// precomputation in some cases and we do not wish to preform that computation
    /// repeatedly.
    pub fn modadd(mut self, a: &mut Self, b: &mut Self) -> Result<Self, Error> {
        if a.is_zero() {
            return b.try_clone();
        }
        if b.is_zero() {
            return a.try_clone();
        }

        if self.0.mont_ctx.is_none() {
            self.precomp_mont_ctx()?;
        }
        // HACL notes say the caller is responsible for ensuring
        // that a < n and b < n.
        // This is where we take on our responsibility
        let a = a.mod_reduce(&mut self)?;
        let b = b.mod_reduce(&mut self)?;

        let result_handle = HaclBnHandle::new(BN_BITSIZE)?;

        let ah = a.0.handle.as_ref().ok_or(Error::ShouldNotHappen)?;
        let bh = b.0.handle.as_ref().ok_or(Error::ShouldNotHappen)?;
        let nh = self.0.handle.as_ref().ok_or(Error::ShouldNotHappen)?;

        unsafe {
            let n = nh.mut_ptr();
            let a = ah.mut_ptr();
            let b = bh.mut_ptr();
            let res = result_handle.mut_ptr();
            Hacl_Bignum4096_add_mod(n, a, b, res)
        }
        let zero_one_other = result_handle.zero_one_other()?;

        Ok(Self(Bui {
            zero_one_other,
            handle: Some(result_handle),
            mont_ctx: None,
        }))
    }

    pub fn modpow(&self, exponent: &Self, modulus: &Modulus) -> Result<Self, Error> {
        //! `(self ^ exponent) % modulus`
        //!
        //! `modulus` must be [mutable](#mutability) to allow for some precomputation on itself.
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

        // Lets get the unwrapped handles
        let base_handle = self.0.handle.as_ref().ok_or(Error::NoHandle)?;
        let exp_handle = exponent.0.handle.as_ref().ok_or(Error::NoHandle)?;

        // And the pointer for where the result goes.
        // HACL calls the size parameter `bBits`
        #[allow(non_snake_case)]
        let bBits = 8 * Self::BN_BYTE_LENGTH;

        let result_handle = HaclBnHandle::new(BN_BITSIZE)?;

        let k = modulus.0.mont_ctx.as_ref().ok_or(Error::ShouldNotHappen)?.0;
        unsafe {
            // Hacl arguments are for a^b in modular
            // context k putting result in res
            let a = base_handle.mut_ptr();
            let b = exp_handle.mut_ptr();
            let res = result_handle.mut_ptr();
            Hacl_Bignum4096_mod_exp_consttime_precomp(
                k,            // Montgomery context
                a,            // base
                bBits as u32, // bit length of result
                b,            // exponent
                res,          // pointer to where result goes.
            );
        }

        let zero_one_other = result_handle.zero_one_other()?;

        Ok(Self(Bui {
            zero_one_other,
            handle: Some(result_handle),
            mont_ctx: None,
        }))
    }

    /// `self % modulus`
    ///
    /// # Errors
    /// - `BadModulus` if self < 2 or if self is even.
    /// - `HaclError` if something some Hacl call returned an error
    ///
    /// Despite the [mutability](#mutability) of `self` and `modulus`
    /// their numeric values don't change.
    pub fn mod_reduce(&mut self, modulus: &mut Self) -> Result<Self, Error> {
        if modulus.0.mont_ctx.is_none() {
            modulus.precomp_mont_ctx()?;
        }

        if self.0.handle.is_none() {
            self.ensure_handle()?;
        }
        let base = self.supersize()?;
        let a = base.0.handle.ok_or(Error::NoHandle)?;

        let handle = HaclBnHandle::new(BN_BITSIZE)?;
        let k = modulus.0.mont_ctx.as_ref().ok_or(Error::ShouldNotHappen)?.0;
        unsafe {
            let a = a.mut_ptr();
            let res = handle.mut_ptr();
            Hacl_Bignum4096_mod_precomp(k, a, res);
        }

        let zero_one_other = handle.zero_one_other()?;
        Ok(Self(Bui {
            zero_one_other,
            handle: Some(handle),
            mont_ctx: None,
        }))
    }

    /// `self = self % modulus`
    ///
    /// This method is not yet tested.
    ///
    /// self is updated with its modular reduction mod modulus.
    ///
    /// modulus does not have its value changed despite its mutability which is
    /// used for updating some precomputation if needed.
    pub fn mod_reduce_mut(&mut self, modulus: &mut Self) -> Result<(), Error> {
        if modulus.0.mont_ctx.is_none() {
            modulus.precomp_mont_ctx()?;
        }

        let handle: HaclBnHandle = HaclBnHandle::new(BN_BITSIZE)?;
        let a = self.0.handle.as_ref().ok_or(Error::NoHandle)?;

        let k = modulus.0.mont_ctx.as_ref().ok_or(Error::ShouldNotHappen)?.0;
        unsafe {
            let a = a.mut_ptr();
            let res = handle.mut_ptr();
            Hacl_Bignum4096_mod_precomp(k, a, res);
        }

        self.0.zero_one_other = handle.zero_one_other()?;
        self.0.handle = Some(handle);
        self.0.mont_ctx = None;

        Ok(())
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
            let a_trim = trimmed_left(&t.a);
            let b_trim = trimmed_left(&t.b);

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
