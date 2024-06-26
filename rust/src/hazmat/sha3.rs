use hacl_sys::{
    Hacl_Hash_SHA3_sha3_224, Hacl_Hash_SHA3_sha3_256, Hacl_Hash_SHA3_sha3_384,
    Hacl_Hash_SHA3_sha3_512, Hacl_Hash_SHA3_shake128, Hacl_Hash_SHA3_shake256,
};

/// SHA3 224
pub fn sha224(payload: &[u8]) -> [u8; 28] {
    let mut digest = [0u8; 28];
    unsafe {
        Hacl_Hash_SHA3_sha3_224(
            digest.as_mut_ptr(),
            payload.as_ptr() as _,
            payload.len().try_into().unwrap(),
        );
    }
    digest
}

/// SHA3 256
pub fn sha256(payload: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    unsafe {
        Hacl_Hash_SHA3_sha3_256(
            digest.as_mut_ptr(),
            payload.as_ptr() as _,
            payload.len().try_into().unwrap(),
        );
    }
    digest
}

/// SHA3 384
pub fn sha384(payload: &[u8]) -> [u8; 48] {
    let mut digest = [0u8; 48];
    unsafe {
        Hacl_Hash_SHA3_sha3_384(
            digest.as_mut_ptr(),
            payload.as_ptr() as _,
            payload.len().try_into().unwrap(),
        );
    }
    digest
}

/// SHA3 512
pub fn sha512(payload: &[u8]) -> [u8; 64] {
    let mut digest = [0u8; 64];
    unsafe {
        Hacl_Hash_SHA3_sha3_512(
            digest.as_mut_ptr(),
            payload.as_ptr() as _,
            payload.len().try_into().unwrap(),
        );
    }
    digest
}

/// SHAKE 128
pub fn shake128<const BYTES: usize>(data: &[u8]) -> [u8; BYTES] {
    let mut out = [0u8; BYTES];
    unsafe {
        Hacl_Hash_SHA3_shake128(
            out.as_mut_ptr(),
            BYTES as u32,
            data.as_ptr() as _,
            data.len() as u32,
        );
    }
    out
}

/// SHAKE 256
///
/// Note that the output length `BYTES` must fit into 32 bit. If it is longer,
/// the output will only return `u32::MAX` bytes.
pub fn shake256<const BYTES: usize>(data: &[u8]) -> [u8; BYTES] {
    let mut out = [0u8; BYTES];
    unsafe {
        Hacl_Hash_SHA3_shake256(
            out.as_mut_ptr(),
            BYTES as u32,
            data.as_ptr() as _,
            data.len() as u32,
        );
    }
    out
}
