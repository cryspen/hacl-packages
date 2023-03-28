use hacl_sys::*;

use crate::digest::Algorithm as Digest;

/// RSA PSS Errors
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// Error while trying to sign something.
    SigningError,

    /// The input exceeds tha maximum input length
    InputTooLarge,

    /// The provided key does not match the used [`KeySize`].
    InvalidKeySize,

    /// The signature verification failed.
    InvalidSignature,
}

/// The key size is the bit/byte-size of the modulus N.
/// Note that the values are bytes but the names are in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum KeySize {
    /// N = 2048 bits | 256 bytes
    N2048 = 256,

    /// N = 3072 bits | 384 bytes
    N3072 = 384,

    /// N = 4096 bits | 512 bytes
    N4096 = 512,

    /// N = 6144 bits | 768 bytes
    N6144 = 768,

    /// N = 8192 bits | 1024 bytes
    N8192 = 1024,
}

impl TryFrom<usize> for KeySize {
    type Error = Error;
    fn try_from(s: usize) -> Result<KeySize, Self::Error> {
        match s {
            256 => Ok(Self::N2048),
            384 => Ok(Self::N3072),
            512 => Ok(Self::N4096),
            768 => Ok(Self::N6144),
            1024 => Ok(Self::N8192),
            _ => Err(Error::InvalidKeySize),
        }
    }
}

/// An RSA-PSS public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    n: Vec<u8>,
}

impl PublicKey {
    /// Create a new [`PublicKey`] from a byte slice.
    ///
    /// Returns an error if the length of the byte slice is not equal to the
    /// `KEY_SIZE`.
    pub fn new(key_size: KeySize, n: &[u8]) -> Result<Self, Error> {
        if n.len() != key_size as usize {
            return Err(Error::InvalidKeySize);
        }
        Ok(Self { n: n.into() })
    }
}

/// An RSA-PSS private key.
/// The private key holds a [`PublicKey`] with the public modulus.
pub struct PrivateKey<'a> {
    pk: &'a PublicKey,
    d: Vec<u8>,
}

impl<'a> PrivateKey<'a> {
    ///Create a new [`PrivateKey`] from a byte slice and a public key.
    ///
    /// Returns an error if the length of the byte slice is not equal to the
    /// key/modulus size.
    pub fn new(pk: &'a PublicKey, d: &[u8]) -> Result<Self, Error> {
        if pk.n.len() != d.len() {
            return Err(Error::InvalidKeySize);
        }
        Ok(Self { pk, d: d.into() })
    }
}

// Size of e.
const E_BITS: u32 = 24;

// We only support this e.
const E: [u8; 3] = [0x01, 0x00, 0x01];

/// Sign the provided `msg` with the `private_key` using the `hash_algorithm`
/// and `salt`.
///
/// Returns an error if any of the inputs are invalid and the signature as byte
/// array.
pub fn sign(
    hash_algorithm: Digest,
    private_key: &PrivateKey,
    salt: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    if salt.len() > (u32::MAX as usize) || msg.len() > (u32::MAX as usize) {
        return Err(Error::InputTooLarge);
    }

    let key_len = private_key.d.len();
    let mut signature = vec![0; key_len];
    let key_size_bits = (key_len as u32) * 8;

    unsafe {
        let skey = Hacl_RSAPSS_new_rsapss_load_skey(
            key_size_bits,
            E_BITS,
            key_size_bits,
            private_key.pk.n.as_ptr() as _,
            E.as_ptr() as _,
            private_key.d.as_ptr() as _,
        );

        if !Hacl_RSAPSS_rsapss_sign(
            hash_algorithm as u8,
            key_size_bits,
            E_BITS,
            key_size_bits,
            skey,
            salt.len() as u32,
            salt.as_ptr() as _,
            msg.len() as u32,
            msg.as_ptr() as _,
            signature.as_mut_ptr(),
        ) {
            return Err(Error::SigningError);
        }
    }
    Ok(signature)
}

/// Verify the `signature` on the `msg` with the `public_key` using the
/// `hash_algorithm` and `salt_len`.
///
/// Returns an error if any of the inputs are invalid or the signature is
/// invalid.
#[must_use = "The result of the signature verification must be used."]
pub fn verify(
    hash_algorithm: Digest,
    public_key: &PublicKey,
    signature: &[u8],
    msg: &[u8],
    salt_len: usize,
) -> Result<(), Error> {
    let key_size_bits = (public_key.n.len() as u32) * 8;
    unsafe {
        let pkey = Hacl_RSAPSS_new_rsapss_load_pkey(
            key_size_bits,
            E_BITS,
            public_key.n.as_ptr() as _,
            E.as_ptr() as _,
        );
        if Hacl_RSAPSS_rsapss_verify(
            hash_algorithm as u8,
            key_size_bits,
            E_BITS,
            pkey,
            salt_len as u32,
            signature.len() as u32,
            signature.as_ptr() as _,
            msg.len() as u32,
            msg.as_ptr() as _,
        ) {
            return Ok(());
        }
    }
    Err(Error::InvalidSignature)
}
