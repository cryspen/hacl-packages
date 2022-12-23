//! Authenticated Encryption with Associated Data (AEAD)
//!
//! This module implements AES-GCM 128 and 256, and Chacha20Poly1305.
//!
//! # Usage
//! This module provides two APIs
//!
//! ## Aead with key state
//! ```rust
//! use hacl_star::aead::{Aead, Algorithm, Error};
//!
//! let key = [0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc,
//!            0xf3, 0x48, 0x43, 0xda, 0xb9, 0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea,
//!            0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9];
//! let cipher = match Aead::new(Algorithm::Chacha20Poly1305, &key) {
//!    Ok(c) => c,
//!    Err(e) => panic!("Error instantiating AEAD.\n{:?}", e),
//! };
//!
//! let iv = [0x02, 0x83, 0x18, 0xab, 0xc1, 0x82, 0x40, 0x29, 0x13, 0x81, 0x41, 0xa2];
//! let msg = [0x00, 0x1d, 0x0c, 0x23, 0x12, 0x87, 0xc1, 0x18, 0x27, 0x84, 0x55, 0x4c, 0xa3, 0xa2, 0x19, 0x08];
//! let aad = [];
//!
//! let (ciphertext, tag) = match cipher.encrypt(&msg, &iv, &aad) {
//!     Ok(r) => r,
//!     Err(e) => panic!("Error encrypting.\n{:?}", e),
//! };
//!
//! let msg_ = match cipher.decrypt(&ciphertext, &tag, &iv, &aad) {
//!     Ok(r) => r,
//!     Err(e) => panic!("Error decrypting.\n{:?}", e),
//! };
//!
//! assert_eq!(&msg[..], &msg_[..]);
//! ```
//!
//! ## Single-shot API
//! ```rust
//! use hacl_star::aead::{self, Algorithm};
//!
//! let key = [0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc,
//!            0xf3, 0x48, 0x43, 0xda, 0xb9, 0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea,
//!            0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda, 0xb9];
//! let iv = [0x02, 0x83, 0x18, 0xab, 0xc1, 0x82, 0x40, 0x29, 0x13, 0x81, 0x41, 0xa2];
//! let msg = [0x00, 0x1d, 0x0c, 0x23, 0x12, 0x87, 0xc1, 0x18, 0x27, 0x84, 0x55, 0x4c, 0xa3, 0xa2, 0x19, 0x08];
//! let aad = [];
//!
//! let (ciphertext, tag) = match aead::encrypt(Algorithm::Chacha20Poly1305, &key, &msg, &iv, &aad) {
//!    Ok(r) => r,
//!    Err(e) => panic!("Error encrypting.\n{:?}", e),
//! };
//!
//! let msg_ = match aead::decrypt(Algorithm::Chacha20Poly1305, &key, &ciphertext, &tag, &iv, &aad) {
//!     Ok(r) => r,
//!     Err(e) => panic!("Error decrypting.\n{:?}", e),
//! };
//!
//! assert_eq!(&msg[..], &msg_[..]);
//! ```
//!

use std::convert::TryInto;

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

use hacl_star_sys::*;

/// The AEAD Algorithm Identifier.
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[repr(u32)]
// ANCHOR: aead_algorithm
pub enum Algorithm {
    /// AES GCM 128
    Aes128Gcm = Spec_Agile_AEAD_AES128_GCM,

    /// AES GCM 256
    Aes256Gcm = Spec_Agile_AEAD_AES256_GCM,

    /// ChaCha20 Poly1305
    Chacha20Poly1305 = Spec_Agile_AEAD_CHACHA20_POLY1305,
}
// ANCHOR_END: aead_algorithm

impl From<u8> for Algorithm {
    fn from(v: u8) -> Algorithm {
        match v {
            0 => Algorithm::Aes128Gcm,
            1 => Algorithm::Aes256Gcm,
            2 => Algorithm::Chacha20Poly1305,
            _ => panic!("Unknown AEAD mode {}", v),
        }
    }
}

impl From<Algorithm> for Spec_Agile_AEAD_alg {
    fn from(v: Algorithm) -> Spec_Agile_AEAD_alg {
        match v {
            Algorithm::Aes128Gcm => Spec_Agile_AEAD_AES128_GCM as Spec_Agile_AEAD_alg,
            Algorithm::Aes256Gcm => Spec_Agile_AEAD_AES256_GCM as Spec_Agile_AEAD_alg,
            Algorithm::Chacha20Poly1305 => Spec_Agile_AEAD_CHACHA20_POLY1305 as Spec_Agile_AEAD_alg,
        }
    }
}

impl Algorithm {
    /// Get the key size of the `Algorithm` in bytes.
    #[inline]
    pub const fn key_size(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::Aes256Gcm => 32,
            Algorithm::Chacha20Poly1305 => 32,
        }
    }

    /// Get the tag size of the `Algorithm` in bytes.
    #[inline]
    pub const fn tag_size(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::Aes256Gcm => 16,
            Algorithm::Chacha20Poly1305 => 16,
        }
    }

    /// Get the nonce size of the `Algorithm` in bytes.
    #[inline]
    pub const fn nonce_size(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 12,
            Algorithm::Aes256Gcm => 12,
            Algorithm::Chacha20Poly1305 => 12,
        }
    }
}

/// AEAD Errors
#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInit = 0,
    InvalidAlgorithm = 1,
    InvalidCiphertext = 2,
    InvalidNonce = 3,
    UnsupportedConfig = 4,
    Encrypting = 5,
    Decrypting = 6,
    InvalidKeySize = 7,
    InvalidTagSize = 8,
}

/// The Aead struct allows to re-use a key without having to initialize it
/// every time.
pub struct Aead {
    alg: Algorithm,
    c_state: Option<*mut EverCrypt_AEAD_state_s>,
}

/// Ciphertexts are byte vectors.
pub type Ciphertext = Vec<u8>;

pub type Aes128Key = [u8; Algorithm::key_size(Algorithm::Aes128Gcm)];
pub type Aes256Key = [u8; Algorithm::key_size(Algorithm::Aes256Gcm)];
pub type Chacha20Key = [u8; Algorithm::key_size(Algorithm::Chacha20Poly1305)];
pub type Tag = [u8; 16];

/// Associated data are byte arrays.
pub type Aad = [u8];

// Check hardware support for HACL* AES implementation.
pub unsafe fn hacl_aes_available() -> bool {
    EverCrypt_AutoConfig2_has_pclmulqdq()
        && EverCrypt_AutoConfig2_has_avx()
        && EverCrypt_AutoConfig2_has_sse()
        && EverCrypt_AutoConfig2_has_movbe()
        && EverCrypt_AutoConfig2_has_aesni()
}

impl Aead {
    fn set_key_(&mut self, k: &[u8]) -> Result<(), Error> {
        let state = unsafe {
            let mut state_ptr: *mut EverCrypt_AEAD_state_s = std::ptr::null_mut();
            let e = EverCrypt_AEAD_create_in(self.alg.into(), &mut state_ptr, k.as_ptr() as _);
            if e != 0 {
                return Err(Error::InvalidInit);
            }
            state_ptr
        };
        self.c_state = Some(state);
        Ok(())
    }

    /// Create a new Aead cipher with the given Algorithm `alg` and key `k`.
    /// If the algorithm is not supported or the state generation fails, this
    /// function returns an `Error`.
    ///
    /// To get an Aead instance without setting a key immediately see `init`.
    pub fn new(alg: Algorithm, k: &[u8]) -> Result<Self, Error> {
        // Check key lengths. Evercrypt is not doing this.
        if k.len() != alg.key_size() {
            return Err(Error::InvalidKeySize);
        }

        unsafe {
            // Make sure this happened.
            EverCrypt_AutoConfig2_init();
        }
        let mut out = Self::init(alg)?;
        out.set_key_(k)?;
        Ok(out)
    }

    /// Initialize a new Aead object without a key.
    /// Use `set_key` to do so later.
    pub fn init(mode: Algorithm) -> Result<Self, Error> {
        if unsafe {
            // Make sure this happened.
            EverCrypt_AutoConfig2_init();

            // Make sure the algorithm is supported
            (mode == Algorithm::Aes128Gcm || mode == Algorithm::Aes256Gcm) && !hacl_aes_available()
        } {
            return Err(Error::UnsupportedConfig);
        }
        Ok(Self {
            alg: mode,
            c_state: None,
        })
    }

    /// Set the key for this instance.
    /// This consumes the Aead and returns a new instance with the key.
    pub fn set_key(self, k: &[u8]) -> Result<Self, Error> {
        Self::new(self.alg, k)
    }

    /// Generate a new random key for this instance.
    /// This consumes the Aead and returns a new instance with the key.
    pub fn set_random_key(&mut self) -> Result<(), Error> {
        self.set_key_(&self.key_gen())
    }

    /// Generate a random key.
    pub fn key_gen(&self) -> Vec<u8> {
        key_gen(self.alg)
    }

    /// Generate a nonce.
    pub fn nonce_gen(&self) -> Vec<u8> {
        nonce_gen(self.alg)
    }

    /// Get the nonce size of this Aead in bytes.
    pub const fn nonce_size(&self) -> usize {
        self.alg.nonce_size()
    }

    /// Get the key size of this Aead in bytes.
    pub const fn key_size(&self) -> usize {
        self.alg.key_size()
    }

    /// Get the tag size of this Aead in bytes.
    pub const fn tag_size(&self) -> usize {
        self.alg.tag_size()
    }

    /// Encrypt with the algorithm and key of this Aead.
    /// Returns `(ctxt, tag)` or an `Error`.
    pub fn encrypt(
        &self,
        msg: &[u8],
        iv: &[u8],
        aad: &Aad,
    ) -> Result<(Ciphertext, Vec<u8>), Error> {
        if iv.len() != self.nonce_size() {
            return Err(Error::InvalidNonce);
        }

        let mut ctxt = vec![0u8; msg.len()];
        let mut tag = vec![0u8; self.tag_size()];
        unsafe {
            EverCrypt_AEAD_encrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                msg.as_ptr() as _,
                msg.len() as u32,
                ctxt.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
        }
        Ok((ctxt, tag))
    }

    /// Encrypt with the algorithm and key of this Aead.
    /// Returns `(ctxt || tag)` or an `Error`.
    /// This is more efficient if the tag needs to be appended to the cipher text.
    // ANCHOR: aead_encrypt_combined
    pub fn encrypt_combined(&self, msg: &[u8], iv: &[u8], aad: &Aad) -> Result<Ciphertext, Error> {
        // ANCHOR_END: aead_encrypt_combined
        if iv.len() != self.nonce_size() {
            return Err(Error::InvalidNonce);
        }

        // combined cipher text and tag
        let mut ctxt = vec![0u8; msg.len() + self.tag_size()];
        unsafe {
            EverCrypt_AEAD_encrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                msg.as_ptr() as _,
                msg.len() as u32,
                ctxt.as_mut_ptr(),
                ctxt.as_mut_ptr().offset(msg.len().try_into().unwrap()),
            );
        }
        Ok(ctxt)
    }

    /// Encrypt with the algorithm and key of this Aead.
    /// Returns the cipher text in the `payload` and a `tag` or an `Error`.
    // ANCHOR: aead_encrypt_in_place
    pub fn encrypt_in_place(
        &self,
        payload: &mut [u8],
        iv: &[u8],
        aad: &Aad,
    ) -> Result<Vec<u8>, Error> {
        // ANCHOR_END: aead_encrypt_in_place
        if iv.len() != self.nonce_size() {
            return Err(Error::InvalidNonce);
        }

        // The tag
        let mut tag = vec![0u8; self.tag_size()];
        unsafe {
            EverCrypt_AEAD_encrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                payload.as_ptr() as _,
                payload.len() as u32,
                payload.as_ptr() as _,
                tag.as_mut_ptr(),
            );
        }
        Ok(tag)
    }

    #[inline]
    fn _decrypt_checks(&self, tag: &[u8], iv: &[u8]) -> Result<(), Error> {
        if iv.len() != 12 {
            return Err(Error::InvalidNonce);
        }
        if tag.len() != self.tag_size() {
            return Err(Error::InvalidTagSize);
        }
        Ok(())
    }

    #[inline]
    fn _decrypt(&self, ctxt: &[u8], tag: &[u8], iv: &[u8], aad: &Aad) -> Result<Vec<u8>, Error> {
        self._decrypt_checks(tag, iv)?;

        let mut msg = vec![0u8; ctxt.len()];
        let r = unsafe {
            EverCrypt_AEAD_decrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                ctxt.as_ptr() as _,
                ctxt.len() as u32,
                tag.as_ptr() as _,
                msg.as_mut_ptr(),
            )
        };
        if r as u32 != EverCrypt_Error_Success {
            Err(Error::InvalidCiphertext)
        } else {
            Ok(msg)
        }
    }

    /// Decrypt with the algorithm and key of this Aead.
    /// Returns `msg` or an `Error`.
    pub fn decrypt(&self, ctxt: &[u8], tag: &[u8], iv: &[u8], aad: &Aad) -> Result<Vec<u8>, Error> {
        self._decrypt(ctxt, tag, iv, aad)
    }

    /// Decrypt with the algorithm and key of this Aead.
    /// Returns `msg` or an `Error`.
    /// This takes the combined ctxt || tag as input and might be more efficient
    /// than `decrypt`.
    // ANCHOR: aead_decrypt_combined
    pub fn decrypt_combined(&self, ctxt: &[u8], iv: &[u8], aad: &Aad) -> Result<Vec<u8>, Error> {
        // ANCHOR_END: aead_decrypt_combined
        if ctxt.len() < self.tag_size() {
            return Err(Error::InvalidTagSize);
        }
        let msg_len = ctxt.len() - self.tag_size();
        let tag = &ctxt[msg_len..];
        let ctxt = &ctxt[..msg_len];
        self._decrypt(ctxt, tag, iv, aad)
    }

    /// Decrypt with the algorithm and key of this Aead.
    ///
    /// Returns an `Error` if decryption failed. The decrypted `payload` is written
    /// into `payload`.
    // ANCHOR: aead_decrypt_in_place
    pub fn decrypt_in_place(
        &self,
        payload: &mut [u8],
        tag: &[u8],
        iv: &[u8],
        aad: &Aad,
    ) -> Result<(), Error> {
        // ANCHOR_END: aead_decrypt_in_place
        self._decrypt_checks(tag, iv)?;

        let r = unsafe {
            EverCrypt_AEAD_decrypt(
                self.c_state.unwrap(),
                iv.as_ptr() as _,
                self.nonce_size().try_into().unwrap(),
                aad.as_ptr() as _,
                aad.len() as u32,
                payload.as_ptr() as _,
                payload.len() as u32,
                tag.as_ptr() as _,
                payload.as_mut_ptr(),
            )
        };
        if r as u32 != EverCrypt_Error_Success {
            Err(Error::InvalidCiphertext)
        } else {
            Ok(())
        }
    }
}

impl Drop for Aead {
    fn drop(&mut self) {
        if let Some(c_state) = self.c_state {
            unsafe { EverCrypt_AEAD_free(c_state) }
        }
    }
}

// Single-shot APIs

/// Single-shot API for AEAD encryption.
pub fn encrypt(
    alg: Algorithm,
    k: &[u8],
    msg: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<(Ciphertext, Vec<u8>), Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.encrypt(msg, iv, aad)
}

/// Single-shot API for combined AEAD encryption.
pub fn encrypt_combined(
    alg: Algorithm,
    k: &[u8],
    msg: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<Ciphertext, Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.encrypt_combined(msg, iv, aad)
}

/// Single-shot API for in place AEAD encryption.
pub fn encrypt_in_place(
    alg: Algorithm,
    k: &[u8],
    payload: &mut [u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<Vec<u8>, Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.encrypt_in_place(payload, iv, aad)
}

/// Single-shot API for AEAD decryption.
pub fn decrypt(
    alg: Algorithm,
    k: &[u8],
    ctxt: &[u8],
    tag: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<Vec<u8>, Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.decrypt(ctxt, tag, iv, aad)
}

/// Single-shot API for combined AEAD decryption.
pub fn decrypt_combined(
    alg: Algorithm,
    k: &[u8],
    ctxt: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<Vec<u8>, Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.decrypt_combined(ctxt, iv, aad)
}

/// Single-shot API for AEAD decryption in place.
pub fn decrypt_in_place(
    alg: Algorithm,
    k: &[u8],
    payload: &mut [u8],
    tag: &[u8],
    iv: &[u8],
    aad: &Aad,
) -> Result<(), Error> {
    let cipher = Aead::new(alg, k)?;
    cipher.decrypt_in_place(payload, tag, iv, aad)
}

/// Generate a random key.
pub fn key_gen(alg: Algorithm) -> Vec<u8> {
    crate::rand_util::random_vec(alg.key_size())
}

/// Generate a nonce.
pub fn nonce_gen(alg: Algorithm) -> Vec<u8> {
    crate::rand_util::random_vec(alg.nonce_size())
}

// /// Generate a random key.
// pub fn key_gen<const L: usize>() -> [u8; L] {
//     crate::rand_util::random_array()
// }

// /// Generate a nonce.
// pub fn nonce_gen<const L: usize>() -> [u8; L] {
//     crate::rand_util::random_array()
// }
