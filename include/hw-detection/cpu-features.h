
// NOTE: Requires C99
#include <stdbool.h>

// Detect CPU features
bool detect_cpu_features(void);

// Check for a specific CPU feature.
// Requires a call to detect_cpu_features first.
bool aesni_support();
bool clmul_support();
bool sha_support();
bool avx_support();
bool avx2_support();
bool ssse3_support();
bool sse4_1_support();
bool sse4_2_support();
bool arm_neon_support();
bool arm_aes_support();
bool arm_pmull_support();
bool arm_sha1_support();
bool arm_sha2_support();
bool ppc_crypto_support();
