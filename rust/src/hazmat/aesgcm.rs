use hacl_star_sys::{
    EverCrypt_AEAD_create_in, EverCrypt_AEAD_decrypt, EverCrypt_AEAD_encrypt,
    EverCrypt_AEAD_state_s, EverCrypt_AutoConfig2_init, Spec_Agile_AEAD_AES128_GCM,
    Spec_Agile_AEAD_AES256_GCM,
};

pub type Aes128Key = [u8; 16];
pub type Aes256Key = [u8; 32];
pub type Iv = [u8; 12];
pub type Tag = [u8; 16];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    UnsupportedHardware,
    EncryptionError,
    InvalidCiphertext,
}

pub fn hardware_support() -> Result<(), Error> {
    unsafe {
        EverCrypt_AutoConfig2_init();
        if hacl_star_sys::EverCrypt_AutoConfig2_has_aesni()
            && hacl_star_sys::EverCrypt_AutoConfig2_has_pclmulqdq()
            && hacl_star_sys::EverCrypt_AutoConfig2_has_avx()
            && hacl_star_sys::EverCrypt_AutoConfig2_has_sse()
            && hacl_star_sys::EverCrypt_AutoConfig2_has_movbe()
        {
            Ok(())
        } else {
            Err(Error::UnsupportedHardware)
        }
    }
}

macro_rules! implement {
    ($name:ident, $name_dec:ident, $alg:expr, $keytype:ty) => {
        #[must_use]
        pub fn $name(
            key: &$keytype,
            msg_ctxt: &mut [u8],
            iv: Iv,
            aad: &[u8],
        ) -> Result<Tag, Error> {
            let mut tag = Tag::default();
            let ok = unsafe {
                hardware_support()?;

                let mut state_ptr: *mut EverCrypt_AEAD_state_s = std::ptr::null_mut();
                let e = EverCrypt_AEAD_create_in($alg as u8, &mut state_ptr, key.as_ptr() as _);
                if e != 0 {
                    return Err(Error::EncryptionError);
                }
                EverCrypt_AEAD_encrypt(
                    state_ptr,
                    iv.as_ptr() as _,
                    iv.len().try_into().map_err(|_| Error::EncryptionError)?,
                    aad.as_ptr() as _,
                    aad.len().try_into().map_err(|_| Error::EncryptionError)?,
                    msg_ctxt.as_ptr() as _,
                    msg_ctxt
                        .len()
                        .try_into()
                        .map_err(|_| Error::EncryptionError)?,
                    msg_ctxt.as_mut_ptr(),
                    tag.as_mut_ptr(),
                )
            };
            if ok == 0 {
                Ok(tag)
            } else {
                Err(Error::EncryptionError)
            }
        }

        #[must_use]
        pub fn $name_dec(
            key: &$keytype,
            payload: &mut [u8],
            iv: Iv,
            aad: &[u8],
            tag: &Tag,
        ) -> Result<(), Error> {
            let ok = unsafe {
                hardware_support()?;

                let mut state_ptr: *mut EverCrypt_AEAD_state_s = std::ptr::null_mut();
                let e = EverCrypt_AEAD_create_in($alg as u8, &mut state_ptr, key.as_ptr() as _);
                if e != 0 {
                    return Err(Error::EncryptionError);
                }
                EverCrypt_AEAD_decrypt(
                    state_ptr,
                    iv.as_ptr() as _,
                    iv.len().try_into().map_err(|_| Error::EncryptionError)?,
                    aad.as_ptr() as _,
                    aad.len().try_into().map_err(|_| Error::EncryptionError)?,
                    payload.as_ptr() as _,
                    payload
                        .len()
                        .try_into()
                        .map_err(|_| Error::EncryptionError)?,
                    tag.as_ptr() as _,
                    payload.as_mut_ptr(),
                )
            };
            if ok == 0 {
                Ok(())
            } else {
                Err(Error::InvalidCiphertext)
            }
        }
    };
}

implement!(
    encrypt_128,
    decrypt_128,
    Spec_Agile_AEAD_AES128_GCM,
    Aes128Key
);
implement!(
    encrypt_256,
    decrypt_256,
    Spec_Agile_AEAD_AES256_GCM,
    Aes256Key
);