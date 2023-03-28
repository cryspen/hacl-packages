use hacl_sys::{Hacl_Ed25519_sign, Hacl_Ed25519_verify};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    SigningError,
    InvalidSignature,
}

pub fn sign(payload: &[u8], private_key: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut signature = [0u8; 32];
    unsafe {
        Hacl_Ed25519_sign(
            signature.as_mut_ptr(),
            private_key.as_ptr() as _,
            payload.len().try_into().map_err(|_| Error::SigningError)?,
            payload.as_ptr() as _,
        );
    }

    Ok(signature)
}

pub fn verify(payload: &[u8], public_key: &[u8; 32], signature: &[u8; 32]) -> Result<(), Error> {
    if unsafe {
        Hacl_Ed25519_verify(
            public_key.as_ptr() as _,
            payload.len().try_into().map_err(|_| Error::SigningError)?,
            payload.as_ptr() as _,
            signature.as_ptr() as _,
        )
    } {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}
