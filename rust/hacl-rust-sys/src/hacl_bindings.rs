#![allow(dead_code)]

// Include bindgen output
// The bindings are freshly generated on Linux and MacOS builds.
// For Windows the prebuilt bindings.rs from the repository are used.
include!("bindings/bindings.rs");

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EverCrypt_AEAD_state_s {
    r#impl: u8,
    ek: *mut u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____ {
    block_state: *mut EverCrypt_Hash_state_s,
    buf: *mut u8,
    total_len: u64,
}

// bindgen gives us stuff with lots of mutable pointers.
// but these are never mutated after initial creation, so
// we are insisting to rust that this objects are thread safe.
// I hope that that is true. (jgoldberg)
unsafe impl Sync for Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64_s {}
