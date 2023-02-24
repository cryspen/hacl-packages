use hacl_star_sys::{
    Hacl_HMAC_DRBG_create_in, Hacl_HMAC_DRBG_free, Hacl_HMAC_DRBG_generate,
    Hacl_HMAC_DRBG_instantiate, Hacl_HMAC_DRBG_reseed, Hacl_HMAC_DRBG_state,
    Spec_Hash_Definitions_SHA1, Spec_Hash_Definitions_SHA2_256, Spec_Hash_Definitions_SHA2_384,
    Spec_Hash_Definitions_SHA2_512,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    Sha1 = Spec_Hash_Definitions_SHA1 as u8,
    Sha2_256 = Spec_Hash_Definitions_SHA2_256 as u8,
    Sha2_384 = Spec_Hash_Definitions_SHA2_384 as u8,
    Sha2_512 = Spec_Hash_Definitions_SHA2_512 as u8,
}

pub enum Error {
    /// Unable to generate the requested randomness.
    UnableToGenerate,
}

pub struct Drbg {
    state: Hacl_HMAC_DRBG_state,
    alg: Algorithm,
}

impl Drbg {
    /// Create a new DRBG state with the given hash function.
    /// This also initializes the DRBG state with the given entropy, nonce and
    /// personalization string.
    pub fn new(alg: Algorithm, entropy: &[u8], nonce: &[u8], personalization: &str) -> Self {
        let state = unsafe { Hacl_HMAC_DRBG_create_in(alg as u8) };
        unsafe {
            Hacl_HMAC_DRBG_instantiate(
                alg as u8,
                state,
                entropy.len().try_into().unwrap(),
                entropy.as_ptr() as _,
                nonce.len().try_into().unwrap(),
                nonce.as_ptr() as _,
                personalization.len().try_into().unwrap(),
                personalization.as_bytes().as_ptr() as _,
            );
        }
        Self { state, alg }
    }

    /// Reseed the DRBG state.
    ///
    /// It is very unlikely that you will need this function.
    pub fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) {
        unsafe {
            Hacl_HMAC_DRBG_reseed(
                self.alg as u8,
                self.state,
                entropy.len().try_into().unwrap(),
                entropy.as_ptr() as _,
                additional_input.len().try_into().unwrap(),
                additional_input.as_ptr() as _,
            );
        }
    }

    /// Generate random bytes.
    pub fn generate(&mut self, output: &mut [u8], additional_input: &[u8]) -> Result<(), Error> {
        if unsafe {
            Hacl_HMAC_DRBG_generate(
                self.alg as u8,
                output.as_mut_ptr(),
                self.state,
                output.len().try_into().unwrap(),
                additional_input.len().try_into().unwrap(),
                additional_input.as_ptr() as _,
            )
        } {
            Ok(())
        } else {
            Err(Error::UnableToGenerate)
        }
    }
}

impl Drop for Drbg {
    fn drop(&mut self) {
        unsafe { Hacl_HMAC_DRBG_free(self.alg as u8, self.state) };
    }
}
