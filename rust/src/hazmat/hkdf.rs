use hacl_star_sys::{
    Hacl_HKDF_expand_sha2_256, Hacl_HKDF_expand_sha2_512, Hacl_HKDF_extract_sha2_256,
    Hacl_HKDF_extract_sha2_512,
};

macro_rules! impl_hkdf {
    ($name:ident,$name_extract:ident,$name_expand:ident,$extract:expr,$expand:expr,$tag_len:literal) => {
        /// HKDF extract using the `salt`, and the input key material `ikm`.
        /// Returns the pre-key material in an array of tag length.
        ///
        /// Note that this function panics if `salt` or `ikm` is larger than 2**32 bytes.
        pub fn $name_extract(salt: &[u8], ikm: &[u8]) -> [u8; $tag_len] {
            let mut prk = [0u8; $tag_len];
            unsafe {
                $extract(
                    prk.as_mut_ptr(),
                    salt.as_ptr() as _,
                    salt.len().try_into().unwrap(),
                    ikm.as_ptr() as _,
                    ikm.len().try_into().unwrap(),
                );
            }
            prk
        }

        /// HKDF expand using the pre-key material `prk` and `info`. The output length
        /// is defined through the result type.
        /// Returns the key material in an array of length `okm_len`.
        ///
        /// **NOTE:** This function returns an all zero array if the requested output
        ///           size is too large.
        ///
        /// Note that this function panics if `salt`, `ikm`, or `OKM_LEN` is larger than 2**32 bytes.
        pub fn $name_expand<const OKM_LEN: usize>(prk: &[u8], info: &[u8]) -> [u8; OKM_LEN] {
            if OKM_LEN > 255 * 32 {
                // Output size is too large. HACL doesn't catch this.
                return [0u8; OKM_LEN];
            }
            let mut okm = [0u8; OKM_LEN];
            unsafe {
                $expand(
                    okm.as_mut_ptr(),
                    prk.as_ptr() as _,
                    prk.len().try_into().unwrap(),
                    info.as_ptr() as _,
                    info.len().try_into().unwrap(),
                    OKM_LEN.try_into().unwrap(),
                );
            }
            okm
        }

        /// HKDF using the `salt`, input key material `ikm`, `info`. The output length
        /// is defined through the result type.
        /// Calls `extract` and `expand` with the given input.
        ///
        /// Returns the key material in an array of length `okm_len`.
        pub fn $name<const OKM_LEN: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; OKM_LEN] {
            let prk = $name_extract(salt, ikm);
            $name_expand(&prk, info)
        }
    };
}

impl_hkdf!(
    hkdf_sha2_256,
    hkdf_sha2_256_extract,
    hkdf_sha2_256_expand,
    Hacl_HKDF_extract_sha2_256,
    Hacl_HKDF_expand_sha2_256,
    32
);
impl_hkdf!(
    hkdf_sha2_512,
    hkdf_sha2_512_extract,
    hkdf_sha2_512_expand,
    Hacl_HKDF_extract_sha2_512,
    Hacl_HKDF_expand_sha2_512,
    64
);
