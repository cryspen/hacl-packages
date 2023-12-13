/*
  This file was generated by KaRaMeL <https://github.com/FStarLang/karamel>
  KaRaMeL invocation: /Users/jonathan/Code/eurydice/eurydice
  ../libcrux_kyber.llbc F* version: 71f2d632 KaRaMeL version: 8e0595bd
 */

#ifndef __libcrux_kyber_H
#define __libcrux_kyber_H

#include "Eurydice.h"
#include "eurydice_glue.h"

extern const int32_t libcrux_kyber_constants_FIELD_MODULUS;

extern const size_t libcrux_kyber_constants_BITS_PER_COEFFICIENT;

extern const size_t libcrux_kyber_constants_COEFFICIENTS_IN_RING_ELEMENT;

extern const size_t libcrux_kyber_constants_BITS_PER_RING_ELEMENT;

extern const size_t libcrux_kyber_constants_BYTES_PER_RING_ELEMENT;

extern const size_t libcrux_kyber_constants_REJECTION_SAMPLING_SEED_SIZE;

extern const size_t libcrux_kyber_constants_SHARED_SECRET_SIZE;

extern const size_t libcrux_kyber_constants_CPA_PKE_KEY_GENERATION_SEED_SIZE;

extern const size_t libcrux_kyber_constants_H_DIGEST_SIZE;

extern const uint8_t libcrux_kyber_arithmetic_MONTGOMERY_SHIFT;

extern const int32_t libcrux_kyber_arithmetic_MONTGOMERY_R;

uint32_t
libcrux_kyber_arithmetic_get_n_least_significant_bits(uint8_t n,
                                                      uint32_t value);

extern const int64_t libcrux_kyber_arithmetic_BARRETT_SHIFT;

extern const int64_t libcrux_kyber_arithmetic_BARRETT_R;

extern const int64_t libcrux_kyber_arithmetic_BARRETT_MULTIPLIER;

static inline int64_t
core_convert_num__i64_59__from(int32_t x0);

int32_t
libcrux_kyber_arithmetic_barrett_reduce(int32_t value);

extern const uint32_t libcrux_kyber_arithmetic_INVERSE_OF_MODULUS_MOD_R;

int32_t
libcrux_kyber_arithmetic_montgomery_reduce(int32_t value);

int32_t
libcrux_kyber_arithmetic_montgomery_multiply_sfe_by_fer(int32_t fe,
                                                        int32_t fer);

extern const int32_t
  libcrux_kyber_arithmetic_MONTGOMERY_R_SQUARED_MOD_FIELD_MODULUS;

int32_t
libcrux_kyber_arithmetic_to_standard_domain(int32_t mfe);

uint16_t
libcrux_kyber_arithmetic_to_unsigned_representative(int32_t fe);

typedef int32_t libcrux_kyber_arithmetic_PolynomialRingElement[256U];

void
  libcrux_kyber_arithmetic__libcrux_kyber__arithmetic__PolynomialRingElement_1__clone(
    int32_t (*self)[256U],
    int32_t ret[256U]);

extern const int32_t
  libcrux_kyber_arithmetic__libcrux_kyber__arithmetic__PolynomialRingElement__ZERO
    [256U];

#define core_cmp_Less 0
#define core_cmp_Equal 1
#define core_cmp_Greater 2

typedef uint8_t core_cmp_Ordering;

#define core_option_None 0
#define core_option_Some 1

typedef uint8_t core_option_Option__size_t_tags;

typedef struct core_option_Option__size_t_s
{
  core_option_Option__size_t_tags tag;
  size_t f0;
} core_option_Option__size_t;

typedef struct K___size_t_core_option_Option_size_t_s
{
  size_t fst;
  core_option_Option__size_t snd;
} K___size_t_core_option_Option_size_t;

#define core_result_Ok 0
#define core_result_Err 1

typedef uint8_t core_result_Result_____core_num_nonzero_NonZeroUsize_tags;

typedef struct core_result_Result_____core_num_nonzero_NonZeroUsize_s
{
  core_result_Result_____core_num_nonzero_NonZeroUsize_tags tag;
  core_num_nonzero_NonZeroUsize f0;
} core_result_Result_____core_num_nonzero_NonZeroUsize;

static inline size_t
core_clone_impls__usize_5__clone(size_t* x0);

static inline bool
core_cmp_impls__usize_21__eq(size_t* x0, size_t* x1);

static inline bool
core_cmp_impls__usize_21__ne(size_t* x0, size_t* x1);

typedef struct core_option_Option__core_cmp_Ordering_s
{
  core_option_Option__size_t_tags tag;
  core_cmp_Ordering f0;
} core_option_Option__core_cmp_Ordering;

static inline core_option_Option__core_cmp_Ordering
core_cmp_impls__usize_54__partial_cmp(size_t* x0, size_t* x1);

static inline bool
core_cmp_impls__usize_54__lt(size_t* x0, size_t* x1);

static inline bool
core_cmp_impls__usize_54__le(size_t* x0, size_t* x1);

static inline bool
core_cmp_impls__usize_54__ge(size_t* x0, size_t* x1);

static inline bool
core_cmp_impls__usize_54__gt(size_t* x0, size_t* x1);

static inline core_option_Option__size_t
core_iter_range__usize_37__steps_between(size_t* x0, size_t* x1);

static inline core_option_Option__size_t
core_iter_range__usize_37__forward_checked(size_t x0, size_t x1);

static inline core_option_Option__size_t
core_iter_range__usize_37__backward_checked(size_t x0, size_t x1);

static inline size_t
core_iter_range__usize_37__forward_unchecked(size_t x0, size_t x1);

static inline size_t
core_iter_range__usize_37__backward_unchecked(size_t x0, size_t x1);

static inline size_t
core_iter_range__usize_37__forward(size_t x0, size_t x1);

static inline size_t
core_iter_range__usize_37__backward(size_t x0, size_t x1);

uint8_t
libcrux_kyber_compress_compress_message_coefficient(uint16_t fe);

int32_t
libcrux_kyber_compress_compress_ciphertext_coefficient(uint8_t coefficient_bits,
                                                       uint16_t fe);

int32_t
libcrux_kyber_compress_decompress_message_coefficient(int32_t fe);

int32_t
libcrux_kyber_compress_decompress_ciphertext_coefficient(
  uint8_t coefficient_bits,
  int32_t fe);

static inline uint16_t
core_num__u16_7__wrapping_add(uint16_t x0, uint16_t x1);

uint8_t
libcrux_kyber_constant_time_ops_is_non_zero(uint8_t value);

static inline uint8_t
core_num__u8_6__wrapping_sub(uint8_t x0, uint8_t x1);

void
libcrux_kyber_constant_time_ops_select_shared_secret_in_constant_time(
  Eurydice_slice lhs,
  Eurydice_slice rhs,
  uint8_t selector,
  uint8_t ret[32U]);

extern void
libcrux_digest_sha3_512(Eurydice_slice x0, uint8_t x1[64U]);

void
libcrux_kyber_hash_functions_G(Eurydice_slice input, uint8_t ret[64U]);

extern void
libcrux_digest_sha3_256(Eurydice_slice x0, uint8_t x1[32U]);

void
libcrux_kyber_hash_functions_H(Eurydice_slice input, uint8_t ret[32U]);

extern bool
libcrux_platform_simd256_support(void);

static inline uint8_t
core_clone_impls__u8_6__clone(uint8_t* x0);

typedef struct K___uint8_t_uint8_t_uint8_t_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
} K___uint8_t_uint8_t_uint8_t;

K___uint8_t_uint8_t_uint8_t
libcrux_kyber_serialize_compress_coefficients_3(uint16_t coefficient1,
                                                uint16_t coefficient2);

void
libcrux_kyber_serialize_serialize_uncompressed_ring_element(int32_t re[256U],
                                                            uint8_t ret[384U]);

void
libcrux_kyber_serialize_deserialize_to_uncompressed_ring_element(
  Eurydice_slice serialized,
  int32_t ret[256U]);

static uint32_t core_num__u32_8__BITS;

static inline uint32_t
core_clone_impls__u32_8__clone(uint32_t* x0);

static inline bool
core_cmp_impls__u32_24__eq(uint32_t* x0, uint32_t* x1);

static inline bool
core_cmp_impls__u32_24__ne(uint32_t* x0, uint32_t* x1);

static inline core_option_Option__core_cmp_Ordering
core_cmp_impls__u32_60__partial_cmp(uint32_t* x0, uint32_t* x1);

static inline bool
core_cmp_impls__u32_60__lt(uint32_t* x0, uint32_t* x1);

static inline bool
core_cmp_impls__u32_60__le(uint32_t* x0, uint32_t* x1);

static inline bool
core_cmp_impls__u32_60__ge(uint32_t* x0, uint32_t* x1);

static inline bool
core_cmp_impls__u32_60__gt(uint32_t* x0, uint32_t* x1);

static inline core_option_Option__size_t
core_iter_range__u32_33__steps_between(uint32_t* x0, uint32_t* x1);

typedef struct core_option_Option__uint32_t_s
{
  core_option_Option__size_t_tags tag;
  uint32_t f0;
} core_option_Option__uint32_t;

static inline core_option_Option__uint32_t
core_iter_range__u32_33__forward_checked(uint32_t x0, size_t x1);

static inline core_option_Option__uint32_t
core_iter_range__u32_33__backward_checked(uint32_t x0, size_t x1);

static inline uint32_t
core_iter_range__u32_33__forward_unchecked(uint32_t x0, size_t x1);

static inline uint32_t
core_iter_range__u32_33__backward_unchecked(uint32_t x0, size_t x1);

static inline uint32_t
core_iter_range__u32_33__forward(uint32_t x0, size_t x1);

static inline uint32_t
core_iter_range__u32_33__backward(uint32_t x0, size_t x1);

typedef struct core_ops_range_Range__uint32_t_s
{
  uint32_t start;
  uint32_t end;
} core_ops_range_Range__uint32_t;

void
libcrux_kyber_sampling_sample_from_binomial_distribution_2(
  Eurydice_slice randomness,
  int32_t ret[256U]);

static inline int32_t
core_clone_impls__i32_14__clone(int32_t* x0);

static inline bool
core_cmp_impls__i32_30__eq(int32_t* x0, int32_t* x1);

static inline bool
core_cmp_impls__i32_30__ne(int32_t* x0, int32_t* x1);

static inline core_option_Option__core_cmp_Ordering
core_cmp_impls__i32_72__partial_cmp(int32_t* x0, int32_t* x1);

static inline bool
core_cmp_impls__i32_72__lt(int32_t* x0, int32_t* x1);

static inline bool
core_cmp_impls__i32_72__le(int32_t* x0, int32_t* x1);

static inline bool
core_cmp_impls__i32_72__ge(int32_t* x0, int32_t* x1);

static inline bool
core_cmp_impls__i32_72__gt(int32_t* x0, int32_t* x1);

static inline core_option_Option__size_t
core_iter_range__i32_34__steps_between(int32_t* x0, int32_t* x1);

typedef struct core_option_Option__int32_t_s
{
  core_option_Option__size_t_tags tag;
  int32_t f0;
} core_option_Option__int32_t;

static inline core_option_Option__int32_t
core_iter_range__i32_34__forward_checked(int32_t x0, size_t x1);

static inline core_option_Option__int32_t
core_iter_range__i32_34__backward_checked(int32_t x0, size_t x1);

static inline int32_t
core_iter_range__i32_34__forward_unchecked(int32_t x0, size_t x1);

static inline int32_t
core_iter_range__i32_34__backward_unchecked(int32_t x0, size_t x1);

static inline int32_t
core_iter_range__i32_34__forward(int32_t x0, size_t x1);

static inline int32_t
core_iter_range__i32_34__backward(int32_t x0, size_t x1);

typedef struct core_ops_range_Range__int32_t_s
{
  int32_t start;
  int32_t end;
} core_ops_range_Range__int32_t;

void
libcrux_kyber_sampling_sample_from_binomial_distribution_3(
  Eurydice_slice randomness,
  int32_t ret[256U]);

extern const int32_t libcrux_kyber_ntt_ZETAS_TIMES_MONTGOMERY_R[128U];

void
libcrux_kyber_ntt_ntt_at_layer(size_t* zeta_i,
                               int32_t re[256U],
                               size_t layer,
                               size_t initial_coefficient_bound,
                               int32_t ret[256U]);

void
libcrux_kyber_ntt_ntt_at_layer_3(size_t* zeta_i,
                                 int32_t re[256U],
                                 size_t layer,
                                 int32_t ret[256U]);

void
libcrux_kyber_ntt_ntt_binomially_sampled_ring_element(int32_t re[256U],
                                                      int32_t ret[256U]);

void
libcrux_kyber_sampling_rejection_sampling_panic_with_diagnostic(void);

typedef struct core_option_Option__Eurydice_slice_uint8_t_s
{
  core_option_Option__size_t_tags tag;
  Eurydice_slice f0;
} core_option_Option__Eurydice_slice_uint8_t;

void
libcrux_kyber_sampling_sample_from_uniform_distribution(
  uint8_t randomness[840U],
  int32_t ret[256U]);

typedef struct K___int32_t_int32_t_s
{
  int32_t fst;
  int32_t snd;
} K___int32_t_int32_t;

K___int32_t_int32_t
libcrux_kyber_ntt_ntt_multiply_binomials(K___int32_t_int32_t _,
                                         K___int32_t_int32_t _0,
                                         int32_t zeta);

void libcrux_kyber_ntt_ntt_multiply(int32_t (*lhs)[256U],
                                    int32_t (*rhs)[256U],
                                    int32_t ret[256U]);

typedef struct K___uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
  uint8_t f3;
  uint8_t f4;
} K___uint8_t_uint8_t_uint8_t_uint8_t_uint8_t;

K___uint8_t_uint8_t_uint8_t_uint8_t_uint8_t
libcrux_kyber_serialize_compress_coefficients_10(int32_t coefficient1,
                                                 int32_t coefficient2,
                                                 int32_t coefficient3,
                                                 int32_t coefficient4);

typedef struct
  K___uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
  uint8_t f3;
  uint8_t f4;
  uint8_t f5;
  uint8_t f6;
  uint8_t f7;
  uint8_t f8;
  uint8_t f9;
  uint8_t f10;
} K___uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t;

K___uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t_uint8_t
libcrux_kyber_serialize_compress_coefficients_11(int32_t coefficient1,
                                                 int32_t coefficient2,
                                                 int32_t coefficient3,
                                                 int32_t coefficient4,
                                                 int32_t coefficient5,
                                                 int32_t coefficient6,
                                                 int32_t coefficient7,
                                                 int32_t coefficient8);

void
libcrux_kyber_ntt_invert_ntt_at_layer(size_t* zeta_i,
                                      int32_t re[256U],
                                      size_t layer,
                                      int32_t ret[256U]);

void
libcrux_kyber_serialize_deserialize_then_decompress_message(
  uint8_t serialized[32U],
  int32_t ret[256U]);

K___uint8_t_uint8_t_uint8_t_uint8_t_uint8_t
libcrux_kyber_serialize_compress_coefficients_5(uint8_t coefficient2,
                                                uint8_t coefficient1,
                                                uint8_t coefficient4,
                                                uint8_t coefficient3,
                                                uint8_t coefficient5,
                                                uint8_t coefficient7,
                                                uint8_t coefficient6,
                                                uint8_t coefficient8);

typedef struct K___int32_t_int32_t_int32_t_int32_t_s
{
  int32_t fst;
  int32_t snd;
  int32_t thd;
  int32_t f3;
} K___int32_t_int32_t_int32_t_int32_t;

K___int32_t_int32_t_int32_t_int32_t
libcrux_kyber_serialize_decompress_coefficients_10(int32_t byte2,
                                                   int32_t byte1,
                                                   int32_t byte3,
                                                   int32_t byte4,
                                                   int32_t byte5);

void
libcrux_kyber_serialize_deserialize_then_decompress_10(
  Eurydice_slice serialized,
  int32_t ret[256U]);

typedef struct
  K___int32_t_int32_t_int32_t_int32_t_int32_t_int32_t_int32_t_int32_t_s
{
  int32_t fst;
  int32_t snd;
  int32_t thd;
  int32_t f3;
  int32_t f4;
  int32_t f5;
  int32_t f6;
  int32_t f7;
} K___int32_t_int32_t_int32_t_int32_t_int32_t_int32_t_int32_t_int32_t;

K___int32_t_int32_t_int32_t_int32_t_int32_t_int32_t_int32_t_int32_t
libcrux_kyber_serialize_decompress_coefficients_11(int32_t byte2,
                                                   int32_t byte1,
                                                   int32_t byte3,
                                                   int32_t byte5,
                                                   int32_t byte4,
                                                   int32_t byte6,
                                                   int32_t byte7,
                                                   int32_t byte9,
                                                   int32_t byte8,
                                                   int32_t byte10,
                                                   int32_t byte11);

void
libcrux_kyber_serialize_deserialize_then_decompress_11(
  Eurydice_slice serialized,
  int32_t ret[256U]);

void
libcrux_kyber_ntt_ntt_at_layer_3328(size_t* zeta_i,
                                    int32_t re[256U],
                                    size_t layer,
                                    int32_t ret[256U]);

static inline uint8_t
core_ops_bit__u8_29__bitand(uint8_t x0, uint8_t x1);

static inline uint8_t
core_ops_bit__u8_791__shr(uint8_t x0, int32_t x1);

K___int32_t_int32_t
libcrux_kyber_serialize_decompress_coefficients_4(uint8_t* byte);

void
libcrux_kyber_serialize_deserialize_then_decompress_4(Eurydice_slice serialized,
                                                      int32_t ret[256U]);

K___int32_t_int32_t_int32_t_int32_t_int32_t_int32_t_int32_t_int32_t
libcrux_kyber_serialize_decompress_coefficients_5(int32_t byte1,
                                                  int32_t byte2,
                                                  int32_t byte3,
                                                  int32_t byte4,
                                                  int32_t byte5);

void
libcrux_kyber_serialize_deserialize_then_decompress_5(Eurydice_slice serialized,
                                                      int32_t ret[256U]);

void
libcrux_kyber_serialize_compress_then_serialize_message(int32_t re[256U],
                                                        uint8_t ret[32U]);

extern const size_t libcrux_kyber_kyber768_RANK_768;

extern const size_t libcrux_kyber_kyber768_RANKED_BYTES_PER_RING_ELEMENT_768;

extern const size_t libcrux_kyber_kyber768_T_AS_NTT_ENCODED_SIZE_768;

extern const size_t libcrux_kyber_kyber768_VECTOR_U_COMPRESSION_FACTOR_768;

extern const size_t libcrux_kyber_kyber768_C1_BLOCK_SIZE_768;

extern const size_t libcrux_kyber_kyber768_C1_SIZE_768;

extern const size_t libcrux_kyber_kyber768_VECTOR_V_COMPRESSION_FACTOR_768;

extern const size_t libcrux_kyber_kyber768_C2_SIZE_768;

extern const size_t libcrux_kyber_kyber768_CPA_PKE_SECRET_KEY_SIZE_768;

extern const size_t libcrux_kyber_kyber768_CPA_PKE_PUBLIC_KEY_SIZE_768;

extern const size_t libcrux_kyber_kyber768_CPA_PKE_CIPHERTEXT_SIZE_768;

extern const size_t libcrux_kyber_kyber768_SECRET_KEY_SIZE_768;

extern const size_t libcrux_kyber_kyber768_ETA1;

extern const size_t libcrux_kyber_kyber768_ETA1_RANDOMNESS_SIZE;

extern const size_t libcrux_kyber_kyber768_ETA2;

extern const size_t libcrux_kyber_kyber768_ETA2_RANDOMNESS_SIZE;

extern const size_t libcrux_kyber_kyber768_IMPLICIT_REJECTION_HASH_INPUT_SIZE;

void
libcrux_kyber_hash_functions_XOFx4___3size_t(uint8_t input[3U][34U],
                                             uint8_t ret[3U][840U]);

void
libcrux_kyber_matrix_sample_matrix_A___3size_t(uint8_t seed[34U],
                                               bool transpose,
                                               int32_t ret[3U][3U][256U]);

void
libcrux_kyber_ind_cpa_into_padded_array___34size_t(Eurydice_slice slice,
                                                   uint8_t ret[34U]);

void
libcrux_kyber_ind_cpa_into_padded_array___33size_t(Eurydice_slice slice,
                                                   uint8_t ret[33U]);

void
libcrux_kyber_hash_functions_PRF___128size_t(Eurydice_slice input,
                                             uint8_t ret[128U]);

void
libcrux_kyber_sampling_sample_from_binomial_distribution___2size_t(
  Eurydice_slice randomness,
  int32_t ret[256U]);

typedef struct
  K___libcrux_kyber_arithmetic_PolynomialRingElement_3size_t__uint8_t_s
{
  int32_t fst[3U][256U];
  uint8_t snd;
} K___libcrux_kyber_arithmetic_PolynomialRingElement_3size_t__uint8_t;

K___libcrux_kyber_arithmetic_PolynomialRingElement_3size_t__uint8_t
libcrux_kyber_ind_cpa_sample_vector_cbd_then_ntt___3size_t_2size_t_128size_t(
  uint8_t prf_input[33U],
  uint8_t domain_separator);

void
libcrux_kyber_arithmetic_add_to_ring_element___3size_t(int32_t lhs[256U],
                                                       int32_t (*rhs)[256U],
                                                       int32_t ret[256U]);

void libcrux_kyber_matrix_compute_As_plus_e___3size_t(
  int32_t (*matrix_A)[3U][256U],
  int32_t (*s_as_ntt)[256U],
  int32_t (*error_as_ntt)[256U],
  int32_t ret[3U][256U]);

void
libcrux_kyber_ind_cpa_serialize_secret_key___3size_t_1152size_t(
  int32_t key[3U][256U],
  uint8_t ret[1152U]);

void
libcrux_kyber_ind_cpa_serialize_public_key___3size_t_1152size_t_1184size_t(
  int32_t t_as_ntt[3U][256U],
  Eurydice_slice seed_for_a,
  uint8_t ret[1184U]);

typedef struct K___uint8_t_1152size_t__uint8_t_1184size_t__s
{
  uint8_t fst[1152U];
  uint8_t snd[1184U];
} K___uint8_t_1152size_t__uint8_t_1184size_t_;

typedef struct K___Eurydice_slice_uint8_t_Eurydice_slice_uint8_t_s
{
  Eurydice_slice fst;
  Eurydice_slice snd;
} K___Eurydice_slice_uint8_t_Eurydice_slice_uint8_t;

K___uint8_t_1152size_t__uint8_t_1184size_t_
libcrux_kyber_ind_cpa_generate_keypair___3size_t_1152size_t_1184size_t_1152size_t_2size_t_128size_t(
  Eurydice_slice key_generation_seed);

void
libcrux_kyber_serialize_kem_secret_key___2400size_t(
  Eurydice_slice private_key,
  Eurydice_slice public_key,
  Eurydice_slice implicit_rejection_value,
  uint8_t ret[2400U]);

typedef uint8_t libcrux_kyber_types_KyberPrivateKey___2400size_t[2400U];

void
libcrux_kyber_types__libcrux_kyber__types__KyberPrivateKey_SIZE__8__from___2400size_t(
  uint8_t value[2400U],
  uint8_t ret[2400U]);

typedef uint8_t libcrux_kyber_types_KyberPublicKey___1184size_t[1184U];

typedef struct libcrux_kyber_types_KyberKeyPair___2400size_t_1184size_t_s
{
  uint8_t sk[2400U];
  uint8_t pk[1184U];
} libcrux_kyber_types_KyberKeyPair___2400size_t_1184size_t;

libcrux_kyber_types_KyberKeyPair___2400size_t_1184size_t
libcrux_kyber_types__libcrux_kyber__types__KyberKeyPair_PRIVATE_KEY_SIZE__PUBLIC_KEY_SIZE___from___2400size_t_1184size_t(
  uint8_t sk[2400U],
  uint8_t pk[1184U]);

libcrux_kyber_types_KyberKeyPair___2400size_t_1184size_t
libcrux_kyber_generate_keypair___3size_t_1152size_t_2400size_t_1184size_t_1152size_t_2size_t_128size_t(
  uint8_t randomness[64U]);

libcrux_kyber_types_KyberKeyPair___2400size_t_1184size_t
libcrux_kyber_kyber768_generate_key_pair_768(uint8_t randomness[64U]);

void
libcrux_kyber_ind_cpa_into_padded_array___64size_t(Eurydice_slice slice,
                                                   uint8_t ret[64U]);

uint8_t*
  libcrux_kyber_types__libcrux_kyber__types__KyberPublicKey_SIZE__18__as_slice___1184size_t(
    uint8_t (*self)[1184U]);

void
libcrux_kyber_ind_cpa_deserialize_public_key___3size_t_1152size_t(
  Eurydice_slice public_key,
  int32_t ret[3U][256U]);

void
libcrux_kyber_ind_cpa_sample_ring_element_cbd___3size_t_128size_t_2size_t(
  uint8_t* prf_input,
  uint8_t* domain_separator,
  int32_t ret[3U][256U]);

void
libcrux_kyber_ntt_invert_ntt_montgomery___3size_t(int32_t re[256U],
                                                  int32_t ret[256U]);

void libcrux_kyber_matrix_compute_vector_u___3size_t(
  int32_t (*a_as_ntt)[3U][256U],
  int32_t (*r_as_ntt)[256U],
  int32_t (*error_1)[256U],
  int32_t ret[3U][256U]);

void libcrux_kyber_matrix_compute_ring_element_v___3size_t(
  int32_t (*t_as_ntt)[256U],
  int32_t (*r_as_ntt)[256U],
  int32_t (*error_2)[256U],
  int32_t (*message)[256U],
  int32_t ret[256U]);

void
libcrux_kyber_serialize_compress_then_serialize_10___320size_t(
  int32_t re[256U],
  uint8_t ret[320U]);

void
libcrux_kyber_serialize_compress_then_serialize_11___320size_t(
  int32_t re[256U],
  uint8_t ret[320U]);

void
libcrux_kyber_serialize_compress_then_serialize_ring_element_u___10size_t_320size_t(
  int32_t re[256U],
  uint8_t ret[320U]);

void
libcrux_kyber_ind_cpa_compress_then_serialize_u___3size_t_960size_t_10size_t_320size_t(
  int32_t input[3U][256U],
  uint8_t ret[960U]);

void
libcrux_kyber_serialize_compress_then_serialize_4___128size_t(
  int32_t re[256U],
  uint8_t ret[128U]);

void
libcrux_kyber_serialize_compress_then_serialize_5___128size_t(
  int32_t re[256U],
  uint8_t ret[128U]);

void
libcrux_kyber_serialize_compress_then_serialize_ring_element_v___4size_t_128size_t(
  int32_t re[256U],
  uint8_t ret[128U]);

void
libcrux_kyber_ind_cpa_into_padded_array___1088size_t(Eurydice_slice slice,
                                                     uint8_t ret[1088U]);

void
libcrux_kyber_ind_cpa_encrypt___3size_t_1088size_t_1152size_t_960size_t_128size_t_10size_t_4size_t_320size_t_2size_t_128size_t_2size_t_128size_t(
  Eurydice_slice public_key,
  uint8_t message[32U],
  Eurydice_slice randomness,
  uint8_t ret[1088U]);

typedef uint8_t libcrux_kyber_types_KyberCiphertext___1088size_t[1088U];

typedef struct
  K___libcrux_kyber_types_KyberCiphertext__1088size_t___uint8_t_32size_t__s
{
  uint8_t fst[1088U];
  uint8_t snd[32U];
} K___libcrux_kyber_types_KyberCiphertext__1088size_t___uint8_t_32size_t_;

typedef struct
  core_result_Result__uint8_t_32size_t__core_array_TryFromSliceError_s
{
  core_result_Result_____core_num_nonzero_NonZeroUsize_tags tag;
  union
  {
    uint8_t case_Ok[32U];
    core_array_TryFromSliceError case_Err;
  } val;
} core_result_Result__uint8_t_32size_t__core_array_TryFromSliceError;

K___libcrux_kyber_types_KyberCiphertext__1088size_t___uint8_t_32size_t_
  libcrux_kyber_encapsulate___3size_t_1088size_t_1184size_t_1152size_t_960size_t_128size_t_10size_t_4size_t_320size_t_2size_t_128size_t_2size_t_128size_t(
    uint8_t (*public_key)[1184U],
    uint8_t randomness[32U]);

K___libcrux_kyber_types_KyberCiphertext__1088size_t___uint8_t_32size_t_
  libcrux_kyber_kyber768_encapsulate_768(uint8_t (*public_key)[1184U],
                                         uint8_t randomness[32U]);

K___Eurydice_slice_uint8_t_Eurydice_slice_uint8_t
  libcrux_kyber_types__libcrux_kyber__types__KyberPrivateKey_SIZE__12__split_at___2400size_t(
    uint8_t (*self)[2400U],
    size_t mid);

void
libcrux_kyber_serialize_deserialize_then_decompress_ring_element_u___10size_t(
  Eurydice_slice serialized,
  int32_t ret[256U]);

void
libcrux_kyber_ntt_ntt_vector_u___10size_t(int32_t re[256U], int32_t ret[256U]);

void
libcrux_kyber_ind_cpa_deserialize_then_decompress_u___3size_t_1088size_t_960size_t_10size_t(
  uint8_t* ciphertext,
  int32_t ret[3U][256U]);

void
libcrux_kyber_serialize_deserialize_then_decompress_ring_element_v___4size_t(
  Eurydice_slice serialized,
  int32_t ret[256U]);

void
libcrux_kyber_ind_cpa_deserialize_secret_key___3size_t(
  Eurydice_slice secret_key,
  int32_t ret[3U][256U]);

void libcrux_kyber_matrix_compute_message___3size_t(
  int32_t (*v)[256U],
  int32_t (*secret_as_ntt)[256U],
  int32_t (*u_as_ntt)[256U],
  int32_t ret[256U]);

void
libcrux_kyber_ind_cpa_decrypt___3size_t_1088size_t_960size_t_10size_t_4size_t(
  Eurydice_slice secret_key,
  uint8_t* ciphertext,
  uint8_t ret[32U]);

void
libcrux_kyber_ind_cpa_into_padded_array___1120size_t(Eurydice_slice slice,
                                                     uint8_t ret[1120U]);

Eurydice_slice
  libcrux_kyber_types__libcrux_kyber__types__KyberCiphertext_SIZE__1__as_ref___1088size_t(
    uint8_t (*self)[1088U]);

void
libcrux_kyber_hash_functions_PRF___32size_t(Eurydice_slice input,
                                            uint8_t ret[32U]);

uint8_t
libcrux_kyber_constant_time_ops_compare_ciphertexts_in_constant_time___1088size_t(
  Eurydice_slice lhs,
  Eurydice_slice rhs);

void
  libcrux_kyber_decapsulate___3size_t_2400size_t_1152size_t_1184size_t_1088size_t_1152size_t_960size_t_128size_t_10size_t_4size_t_320size_t_2size_t_128size_t_2size_t_128size_t_1120size_t(
    uint8_t (*secret_key)[2400U],
    uint8_t (*ciphertext)[1088U],
    uint8_t ret[32U]);

void libcrux_kyber_kyber768_decapsulate_768(uint8_t (*secret_key)[2400U],
                                            uint8_t (*ciphertext)[1088U],
                                            uint8_t ret[32U]);

extern const size_t libcrux_kyber_KEY_GENERATION_SEED_SIZE;

#define __libcrux_kyber_H_DEFINED
#endif
