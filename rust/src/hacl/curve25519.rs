use hacl_star_sys::EverCrypt_Curve25519_ecdh;

pub enum Error {
    InvalidInput,
}

/// Compute the ECDH with the `private_key` and `public_key`.
///
/// Returns the 32 bytes shared key.
#[must_use]
pub fn ecdh(private_key: &[u8; 32], public_key: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut shared = [0u8; 32];
    let ok = unsafe {
        EverCrypt_Curve25519_ecdh(
            shared.as_mut_ptr(),
            private_key.as_ptr() as _,
            public_key.as_ptr() as _,
        )
    };
    if !ok {
        Err(Error::InvalidInput)
    } else {
        Ok(shared)
    }
}
