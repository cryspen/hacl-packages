//! Bignum
//!
//! This module implements friendlier bignum for 4096 bit bignums
//! 
//! It safely (one hopes) wraps the unsafe Hacl_Bignum operations and provides
//! a struct (type) Bignum that should conceal the nasty pointers to mutable data.

use hacl_rust_sys::*;


#[derive(Debug)]
/// Errors for Bignum operations
pub enum Error {
    DeconversionError,
    ConversionError,
}

pub struct Bignum {
    bn: [u64] // the type that bindgen tells us
}

// We will really want From<whatever-we-use-in-core-for-byte-arrays>
impl From<Vec<u8>> for Bignum {
    fn from(be_bytes: Vec<u8>) -> Self {
        let length:u32 = be_bytes.len() as u32;
        let  bn: [u64];
        unsafe {
            bn = Hacl_Bignum4096_new_bn_from_bytes_be(length, be_bytes.as_mut_ptr());
        };
        Self {bn}
    }
}

impl Bignum {
    /// 
    pub fn to_vec8(&self) -> Result<Vec<u8>, Error> {
        if &self.bn.<*const u64]>::as_ref().len() == 0 {
            return Err(Error::DeconversionError)
        }
        let be_bytes: *mut u8;
        unsafe {
            Hacl_Bignum4096_bn_to_bytes_be(&self.bn, be_bytes);
        }
        Ok(be_bytes.as_ref().to_vec())
    }

}
