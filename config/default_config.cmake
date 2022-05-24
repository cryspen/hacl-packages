set(SOURCES_std ${PROJECT_SOURCE_DIR}/src/Hacl_NaCl.c ${PROJECT_SOURCE_DIR}/src/Hacl_Salsa20.c ${PROJECT_SOURCE_DIR}/src/Hacl_Krmllib.c ${PROJECT_SOURCE_DIR}/src/Hacl_Poly1305_32.c ${PROJECT_SOURCE_DIR}/src/Hacl_Curve25519_51.c ${PROJECT_SOURCE_DIR}/src/Hacl_HMAC_DRBG.c ${PROJECT_SOURCE_DIR}/src/Hacl_Spec.c ${PROJECT_SOURCE_DIR}/src/Hacl_HMAC.c ${PROJECT_SOURCE_DIR}/src/Hacl_Hash_SHA2.c ${PROJECT_SOURCE_DIR}/src/Hacl_Hash_SHA1.c ${PROJECT_SOURCE_DIR}/src/Hacl_Ed25519.c ${PROJECT_SOURCE_DIR}/src/Hacl_Streaming_SHA2.c ${PROJECT_SOURCE_DIR}/src/Hacl_Hash_Base.c ${PROJECT_SOURCE_DIR}/src/Hacl_Hash_Blake2.c ${PROJECT_SOURCE_DIR}/src/Lib_Memzero0.c ${PROJECT_SOURCE_DIR}/src/Hacl_Streaming_Blake2.c ${PROJECT_SOURCE_DIR}/src/Hacl_Bignum256_32.c ${PROJECT_SOURCE_DIR}/src/Hacl_GenericField32.c ${PROJECT_SOURCE_DIR}/src/Hacl_Bignum.c ${PROJECT_SOURCE_DIR}/src/Hacl_Bignum32.c ${PROJECT_SOURCE_DIR}/src/Hacl_Bignum4096_32.c ${PROJECT_SOURCE_DIR}/src/Hacl_Chacha20Poly1305_32.c ${PROJECT_SOURCE_DIR}/src/Hacl_Chacha20.c ${PROJECT_SOURCE_DIR}/src/Hacl_P256.c ${PROJECT_SOURCE_DIR}/src/Hacl_K256_ECDSA.c ${PROJECT_SOURCE_DIR}/src/Hacl_EC_K256.c ${PROJECT_SOURCE_DIR}/src/Hacl_SHA3.c ${PROJECT_SOURCE_DIR}/src/Hacl_Streaming_SHA1.c ${PROJECT_SOURCE_DIR}/src/Hacl_Hash_MD5.c ${PROJECT_SOURCE_DIR}/src/Hacl_HKDF.c ${PROJECT_SOURCE_DIR}/src/Hacl_RSAPSS.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_DRBG.c ${PROJECT_SOURCE_DIR}/src/Lib_RandomBuffer_System.c ${PROJECT_SOURCE_DIR}/src/Lib_Memzero0.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_HMAC.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_Hash.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_AutoConfig2.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_Ed25519.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_Curve25519.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_CTR.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_Error.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_HKDF.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_Cipher.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_Chacha20Poly1305.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_Poly1305.c ${PROJECT_SOURCE_DIR}/src/EverCrypt_AEAD.c)
set(SOURCES_vec256 ${PROJECT_SOURCE_DIR}/src/Hacl_Hash_Blake2b_256.c ${PROJECT_SOURCE_DIR}/src/Hacl_Streaming_Blake2b_256.c ${PROJECT_SOURCE_DIR}/src/Hacl_Chacha20Poly1305_256.c ${PROJECT_SOURCE_DIR}/src/Hacl_Poly1305_256.c ${PROJECT_SOURCE_DIR}/src/Hacl_Chacha20_Vec256.c ${PROJECT_SOURCE_DIR}/src/Hacl_SHA2_Vec256.c)
set(SOURCES_vec128 ${PROJECT_SOURCE_DIR}/src/Hacl_Hash_Blake2s_128.c ${PROJECT_SOURCE_DIR}/src/Hacl_Streaming_Blake2s_128.c ${PROJECT_SOURCE_DIR}/src/Hacl_Bignum4096.c ${PROJECT_SOURCE_DIR}/src/Hacl_Bignum256.c ${PROJECT_SOURCE_DIR}/src/Hacl_Bignum64.c ${PROJECT_SOURCE_DIR}/src/Hacl_GenericField64.c ${PROJECT_SOURCE_DIR}/src/Hacl_Chacha20Poly1305_128.c ${PROJECT_SOURCE_DIR}/src/Hacl_Poly1305_128.c ${PROJECT_SOURCE_DIR}/src/Hacl_Chacha20_Vec128.c ${PROJECT_SOURCE_DIR}/src/Hacl_SHA2_Vec128.c)
set(SOURCES_vale ${PROJECT_SOURCE_DIR}/src/Hacl_Curve25519_64.c)
set(INCLUDES ${PROJECT_SOURCE_DIR}/include/Hacl_NaCl.h ${PROJECT_SOURCE_DIR}/karamel/include/krml/internal/types.h ${PROJECT_SOURCE_DIR}/karamel/include/krml/lowstar_endianness.h ${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal/fstar_uint128_gcc64.h ${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal/FStar_UInt128.h ${PROJECT_SOURCE_DIR}/karamel/include/krml/internal/compat.h ${PROJECT_SOURCE_DIR}/karamel/include/krml/internal/target.h ${PROJECT_SOURCE_DIR}/karamel/include/krml/internal/callconv.h ${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal/FStar_UInt_8_16_32_64.h ${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal/LowStar_Endianness.h ${PROJECT_SOURCE_DIR}/include/Hacl_Salsa20.h ${PROJECT_SOURCE_DIR}/include/Hacl_Krmllib.h ${PROJECT_SOURCE_DIR}/include/evercrypt_targetconfig.h ${PROJECT_SOURCE_DIR}/build/config.h ${PROJECT_SOURCE_DIR}/include/libintvector.h ${PROJECT_SOURCE_DIR}/include/Hacl_Poly1305_32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Curve25519_51.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum25519_51.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Krmllib.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Krmllib.h ${PROJECT_SOURCE_DIR}/include/Hacl_HMAC_DRBG.h ${PROJECT_SOURCE_DIR}/include/Hacl_Spec.h ${PROJECT_SOURCE_DIR}/include/Hacl_HMAC.h ${PROJECT_SOURCE_DIR}/include/Hacl_Impl_Blake2_Constants.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_SHA2.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_SHA1.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Ed25519.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Hash_SHA2.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_SHA2.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Curve25519_51.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Curve25519_51.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Ed25519.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_SHA2.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_Base.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Hash_Blake2.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_Blake2.h ${PROJECT_SOURCE_DIR}/include/Lib_Memzero0.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_Blake2.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_Blake2.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Hash_Blake2b_256.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_Blake2b_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_Blake2b_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_Blake2b_256.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Hash_Blake2s_128.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_Blake2s_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_Blake2s_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_Blake2s_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum256_32.h ${PROJECT_SOURCE_DIR}/include/Hacl_GenericField32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum_Base.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Bignum.h ${PROJECT_SOURCE_DIR}/include/lib_intrinsics.h ${PROJECT_SOURCE_DIR}/include/Hacl_IntTypes_Intrinsics.h ${PROJECT_SOURCE_DIR}/include/Hacl_IntTypes_Intrinsics_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum4096_32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum4096.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum64.h ${PROJECT_SOURCE_DIR}/include/Hacl_GenericField64.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20Poly1305_32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20Poly1305_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Poly1305_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20_Vec128.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Poly1305_128.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Poly1305_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20Poly1305_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Poly1305_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20_Vec256.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Poly1305_256.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Poly1305_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Curve25519_64.h ${PROJECT_SOURCE_DIR}/include/internal/Vale.h ${PROJECT_SOURCE_DIR}/include/curve25519-inline.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_P256.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Spec.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Spec.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_P256.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_K256_ECDSA.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_K256_ECDSA.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum_K256.h ${PROJECT_SOURCE_DIR}/include/Hacl_EC_K256.h ${PROJECT_SOURCE_DIR}/include/Hacl_SHA3.h ${PROJECT_SOURCE_DIR}/include/Hacl_SHA2_Vec128.h ${PROJECT_SOURCE_DIR}/include/Hacl_SHA2_Generic.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_SHA2_Vec128.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_SHA2_Vec128.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_SHA2_Vec256.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_SHA2_Vec256.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Hash_SHA1.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_SHA1.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_SHA1.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Hash_MD5.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_MD5.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_HMAC.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_HMAC.h ${PROJECT_SOURCE_DIR}/include/Hacl_HKDF.h ${PROJECT_SOURCE_DIR}/include/Hacl_RSAPSS.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_DRBG.h ${PROJECT_SOURCE_DIR}/include/Lib_RandomBuffer_System.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_HMAC.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Hash.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_MD5.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_AutoConfig2.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Ed25519.h ${PROJECT_SOURCE_DIR}/include/Hacl_Ed25519.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Curve25519.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_CTR.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Error.h ${PROJECT_SOURCE_DIR}/include/internal/Hacl_Chacha20.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Chacha20.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_HKDF.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Cipher.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Chacha20Poly1305.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Poly1305.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_AEAD.h)
set(PUBLIC_INCLUDES ${PROJECT_SOURCE_DIR}/include/Hacl_NaCl.h ${PROJECT_SOURCE_DIR}/karamel/include/krml/lowstar_endianness.h ${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal/fstar_uint128_gcc64.h ${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal/FStar_UInt128.h ${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal/FStar_UInt_8_16_32_64.h ${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal/LowStar_Endianness.h ${PROJECT_SOURCE_DIR}/include/Hacl_Salsa20.h ${PROJECT_SOURCE_DIR}/include/Hacl_Krmllib.h ${PROJECT_SOURCE_DIR}/include/evercrypt_targetconfig.h ${PROJECT_SOURCE_DIR}/build/config.h ${PROJECT_SOURCE_DIR}/include/libintvector.h ${PROJECT_SOURCE_DIR}/include/Hacl_Poly1305_32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Curve25519_51.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum25519_51.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Krmllib.h ${PROJECT_SOURCE_DIR}/include/Hacl_HMAC_DRBG.h ${PROJECT_SOURCE_DIR}/include/Hacl_Spec.h ${PROJECT_SOURCE_DIR}/include/Hacl_HMAC.h ${PROJECT_SOURCE_DIR}/include/Hacl_Impl_Blake2_Constants.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_SHA2.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_SHA1.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_SHA2.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Curve25519_51.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Ed25519.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_SHA2.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_Base.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_Blake2.h ${PROJECT_SOURCE_DIR}/include/Lib_Memzero0.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_Blake2.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_Blake2.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_Blake2b_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_Blake2b_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_Blake2b_256.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_Blake2s_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_Blake2s_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_Blake2s_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum256_32.h ${PROJECT_SOURCE_DIR}/include/Hacl_GenericField32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum_Base.h ${PROJECT_SOURCE_DIR}/include/lib_intrinsics.h ${PROJECT_SOURCE_DIR}/include/Hacl_IntTypes_Intrinsics.h ${PROJECT_SOURCE_DIR}/include/Hacl_IntTypes_Intrinsics_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum4096_32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum4096.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum64.h ${PROJECT_SOURCE_DIR}/include/Hacl_GenericField64.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20Poly1305_32.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20Poly1305_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Poly1305_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20_Vec128.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Poly1305_128.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20Poly1305_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Poly1305_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Chacha20_Vec256.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Poly1305_256.h ${PROJECT_SOURCE_DIR}/include/Hacl_Curve25519_64.h ${PROJECT_SOURCE_DIR}/include/curve25519-inline.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Spec.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_P256.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_K256_ECDSA.h ${PROJECT_SOURCE_DIR}/include/Hacl_Bignum_K256.h ${PROJECT_SOURCE_DIR}/include/Hacl_EC_K256.h ${PROJECT_SOURCE_DIR}/include/Hacl_SHA3.h ${PROJECT_SOURCE_DIR}/include/Hacl_SHA2_Vec128.h ${PROJECT_SOURCE_DIR}/include/Hacl_SHA2_Generic.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_SHA2_Vec128.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_SHA2_Vec256.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_SHA1.h ${PROJECT_SOURCE_DIR}/include/Hacl_Streaming_SHA1.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Hash_MD5.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_HMAC.h ${PROJECT_SOURCE_DIR}/include/Hacl_HKDF.h ${PROJECT_SOURCE_DIR}/include/Hacl_RSAPSS.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_DRBG.h ${PROJECT_SOURCE_DIR}/include/Lib_RandomBuffer_System.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_HMAC.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Hash.h ${PROJECT_SOURCE_DIR}/include/Hacl_Hash_MD5.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_AutoConfig2.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Ed25519.h ${PROJECT_SOURCE_DIR}/include/Hacl_Ed25519.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Curve25519.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_CTR.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Error.h ${PROJECT_SOURCE_DIR}/include/internal/../Hacl_Chacha20.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_HKDF.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Cipher.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Chacha20Poly1305.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_Poly1305.h ${PROJECT_SOURCE_DIR}/include/EverCrypt_AEAD.h)
set(ALGORITHMS nacl salsa20 aesgcm drbg ed25519 blake2 bignum generic-field chacha20poly1305 curve25519 p256 k256 sha3 sha2 sha1 md5 hmac hkdf rsapss)
set(INCLUDE_PATHS ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/build ${PROJECT_SOURCE_DIR}/karamel/include ${PROJECT_SOURCE_DIR}/karamel/krmllib/dist/minimal ${PROJECT_SOURCE_DIR}/vale/include)
set(TEST_SOURCES ${PROJECT_SOURCE_DIR}/tests/blake2b.cc ${PROJECT_SOURCE_DIR}/tests/blake2s.cc ${PROJECT_SOURCE_DIR}/tests/p256_ecdh.cc ${PROJECT_SOURCE_DIR}/tests/p256_ecdsa.cc ${PROJECT_SOURCE_DIR}/tests/p256k1_ecdsa.cc ${PROJECT_SOURCE_DIR}/tests/chacha20poly1305.cc ${PROJECT_SOURCE_DIR}/tests/ed25519.cc ${PROJECT_SOURCE_DIR}/tests/x25519.cc ${PROJECT_SOURCE_DIR}/tests/hmac.cc ${PROJECT_SOURCE_DIR}/tests/sha2.cc ${PROJECT_SOURCE_DIR}/tests/sha3.cc)
set(VALE_SOURCES_osx ${PROJECT_SOURCE_DIR}/vale/src/cpuid-x86_64-darwin.S ${PROJECT_SOURCE_DIR}/vale/src/sha256-x86_64-darwin.S ${PROJECT_SOURCE_DIR}/vale/src/aesgcm-x86_64-darwin.S ${PROJECT_SOURCE_DIR}/vale/src/aes-x86_64-darwin.S ${PROJECT_SOURCE_DIR}/vale/src/curve25519-x86_64-darwin.S ${PROJECT_SOURCE_DIR}/vale/src/poly1305-x86_64-darwin.S)
set(VALE_SOURCES_linux ${PROJECT_SOURCE_DIR}/vale/src/cpuid-x86_64-linux.S ${PROJECT_SOURCE_DIR}/vale/src/sha256-x86_64-linux.S ${PROJECT_SOURCE_DIR}/vale/src/aesgcm-x86_64-linux.S ${PROJECT_SOURCE_DIR}/vale/src/aes-x86_64-linux.S ${PROJECT_SOURCE_DIR}/vale/src/curve25519-x86_64-linux.S ${PROJECT_SOURCE_DIR}/vale/src/poly1305-x86_64-linux.S)
set(VALE_SOURCES_mingw ${PROJECT_SOURCE_DIR}/vale/src/cpuid-x86_64-mingw.S ${PROJECT_SOURCE_DIR}/vale/src/sha256-x86_64-mingw.S ${PROJECT_SOURCE_DIR}/vale/src/aesgcm-x86_64-mingw.S ${PROJECT_SOURCE_DIR}/vale/src/aes-x86_64-mingw.S ${PROJECT_SOURCE_DIR}/vale/src/curve25519-x86_64-mingw.S ${PROJECT_SOURCE_DIR}/vale/src/poly1305-x86_64-mingw.S)
set(VALE_SOURCES_msvc ${PROJECT_SOURCE_DIR}/vale/src/cpuid-x86_64-msvc.asm ${PROJECT_SOURCE_DIR}/vale/src/sha256-x86_64-msvc.asm ${PROJECT_SOURCE_DIR}/vale/src/aesgcm-x86_64-msvc.asm ${PROJECT_SOURCE_DIR}/vale/src/aes-x86_64-msvc.asm ${PROJECT_SOURCE_DIR}/vale/src/curve25519-x86_64-msvc.asm ${PROJECT_SOURCE_DIR}/vale/src/poly1305-x86_64-msvc.asm)
set(ALGORITHM_TEST_FILES TEST_FILES_blake2 TEST_FILES_p256 TEST_FILES_k256 TEST_FILES_chacha20poly1305 TEST_FILES_ed25519 TEST_FILES_curve25519 TEST_FILES_hmac TEST_FILES_sha2 TEST_FILES_sha3)
set(TEST_FILES_blake2 blake2b.cc blake2s.cc)
set(TEST_FILES_p256 p256_ecdh.cc p256_ecdsa.cc)
set(TEST_FILES_k256 p256k1_ecdsa.cc)
set(TEST_FILES_chacha20poly1305 chacha20poly1305.cc)
set(TEST_FILES_ed25519 ed25519.cc)
set(TEST_FILES_curve25519 x25519.cc)
set(TEST_FILES_hmac hmac.cc)
set(TEST_FILES_sha2 sha2.cc)
set(TEST_FILES_sha3 sha3.cc)
