

enum boringssl_keccak_config_t {
  boringssl_sha3_256,
  boringssl_sha3_512,
  boringssl_shake128,
  boringssl_shake256,
};

// // BORINGSSL_keccak hashes |in_len| bytes from |in| and writes |out_len| bytes
// // of output to |out|. If the |config| specifies a fixed-output function, like
// // SHA3-256, then |out_len| must be the correct length for that function.
// extern void BORINGSSL_keccak(uint8_t *out, size_t out_len,
//                                      const uint8_t *in, size_t in_len,
//                                      enum boringssl_keccak_config_t config);
