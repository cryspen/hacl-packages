use hacl_star_sys::{
    Hacl_Hash_SHA2_hash_224, Hacl_Hash_SHA2_hash_256, Hacl_Hash_SHA2_hash_384,
    Hacl_Hash_SHA2_hash_512,
};

/// SHA2 224
pub fn sha224(payload: &[u8]) -> [u8; 28] {
    let mut digest = [0u8; 28];
    unsafe {
        Hacl_Hash_SHA2_hash_224(
            payload.as_ptr() as _,
            payload.len().try_into().unwrap(),
            digest.as_mut_ptr(),
        );
    }
    digest
}

/// SHA2 256
pub fn sha256(payload: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    unsafe {
        Hacl_Hash_SHA2_hash_256(
            payload.as_ptr() as _,
            payload.len().try_into().unwrap(),
            digest.as_mut_ptr(),
        );
    }
    digest
}

/// SHA2 384
pub fn sha384(payload: &[u8]) -> [u8; 48] {
    let mut digest = [0u8; 48];
    unsafe {
        Hacl_Hash_SHA2_hash_384(
            payload.as_ptr() as _,
            payload.len().try_into().unwrap(),
            digest.as_mut_ptr(),
        );
    }
    digest
}

/// SHA2 512
pub fn sha512(payload: &[u8]) -> [u8; 64] {
    let mut digest = [0u8; 64];
    unsafe {
        Hacl_Hash_SHA2_hash_512(
            payload.as_ptr() as _,
            payload.len().try_into().unwrap(),
            digest.as_mut_ptr(),
        );
    }
    digest
}
