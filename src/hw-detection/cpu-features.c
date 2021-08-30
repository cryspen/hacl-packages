/*
 * Runtime CPU feature detection.
 * This can be used stand-alone at configuration time in CMake.
 * It is also used at runtime to ensure features are actually available.
 *
 * I borrowed some of this from NSS where I wrote it a while back.
 * NOTE: This requires C99 right now for bool
 */

#include "hw-detection/cpu-features.h"

#include <stdint.h>

#if defined(_MSC_VER) && !defined(_M_IX86)
#include <intrin.h> /* for _xgetbv() */
#endif

#if defined(_WIN64) && defined(__aarch64__)
#include <windows.h>
#endif

#if defined(DARWIN)
#include <TargetConditionals.h>
#endif

/* State variables. */
static bool aesni_support_ = false;
static bool clmul_support_ = false;
static bool sha_support_ = false;
static bool avx_support_ = false;
static bool avx2_support_ = false;
static bool ssse3_support_ = false;
static bool sse4_1_support_ = false;
static bool sse4_2_support_ = false;
static bool arm_neon_support_ = false;
static bool arm_aes_support_ = false;
static bool arm_sha1_support_ = false;
static bool arm_sha2_support_ = false;
static bool arm_pmull_support_ = false;
static bool ppc_crypto_support_ = false;

#if ARCHITECTURE == ARCHITECTURE_ID_X86 || ARCHITECTURE == ARCHITECTURE_ID_X64

void cpuid(unsigned long op, unsigned long *eax,
             unsigned long *ebx, unsigned long *ecx,
             unsigned long *edx)
{
    __asm__("xor %%ecx, %%ecx\n\t"
            "cpuid\n\t"
            : "=a"(*eax),
              "=b"(*ebx),
              "=c"(*ecx),
              "=d"(*edx)
            : "0"(op));
}

/*
 * Adapted from the example code in "How to detect New Instruction support in
 * the 4th generation Intel Core processor family" by Max Locktyukhin.
 *
 * XGETBV:
 *   Reads an extended control register (XCR) specified by ECX into EDX:EAX.
 */
static bool
check_xcr0_ymm()
{
    uint32_t xcr0;
#if defined(_MSC_VER)
#if defined(_M_IX86)
    __asm {
        mov ecx, 0
        xgetbv
        mov xcr0, eax
    }
#else
    xcr0 = (uint32_t)_xgetbv(0); /* Requires VS2010 SP1 or later. */
#endif /* _M_IX86 */
#else  /* _MSC_VER */
    /* Old OSX compilers don't support xgetbv. Use byte form. */
    __asm__(".byte 0x0F, 0x01, 0xd0"
            : "=a"(xcr0)
            : "c"(0)
            : "%edx");
#endif /* _MSC_VER */
    /* Check if xmm and ymm state are enabled in XCR0. */
    return (xcr0 & 6) == 6;
}

#define ECX_AESNI (1 << 25)
#define ECX_CLMUL (1 << 1)
#define ECX_XSAVE (1 << 26)
#define ECX_OSXSAVE (1 << 27)
#define ECX_AVX (1 << 28)
#define EBX_AVX2 (1 << 5)
#define EBX_BMI1 (1 << 3)
#define EBX_BMI2 (1 << 8)
#define EBX_SHA (1 << 29)
#define ECX_FMA (1 << 12)
#define ECX_MOVBE (1 << 22)
#define ECX_SSSE3 (1 << 9)
#define ECX_SSE4_1 (1 << 19)
#define ECX_SSE4_2 (1 << 20)
#define AVX_BITS (ECX_XSAVE | ECX_OSXSAVE | ECX_AVX)
#define AVX2_EBX_BITS (EBX_AVX2 | EBX_BMI1 | EBX_BMI2)
#define AVX2_ECX_BITS (ECX_FMA | ECX_MOVBE)

void
CheckX86CPUSupport()
{
    unsigned long eax, ebx, ecx, edx;
    unsigned long eax7, ebx7, ecx7, edx7;
    cpuid(1, &eax, &ebx, &ecx, &edx);
    cpuid(7, &eax7, &ebx7, &ecx7, &edx7);
    aesni_support_ = (ecx & ECX_AESNI) != 0;
    clmul_support_ = (ecx & ECX_CLMUL) != 0;
    sha_support_ = (ebx7 & EBX_SHA) != 0;
    /* For AVX we check AVX, OSXSAVE, and XSAVE
     * as well as XMM and YMM state. */
    avx_support_ = ((ecx & AVX_BITS) == AVX_BITS) && check_xcr0_ymm();
    /* For AVX2 we check AVX2, BMI1, BMI2, FMA, MOVBE.
     * We do not check for AVX above. */
    avx2_support_ = (ebx7 & AVX2_EBX_BITS) == AVX2_EBX_BITS &&
                    (ecx & AVX2_ECX_BITS) == AVX2_ECX_BITS;
    ssse3_support_ = (ecx & ECX_SSSE3) != 0;
    sse4_1_support_ = (ecx & ECX_SSE4_1) != 0;
    sse4_2_support_ = (ecx & ECX_SSE4_2) != 0;
}
#endif /* ARCHITECTURE == ARCHITECTURE_ID_X86 || ARCHITECTURE == ARCHITECTURE_ID_X64 */

// === "Public" API ===

// Detect feature flags and set static variables accordingly.
bool detect_cpu_features(void)
{
#if ARCHITECTURE == ARCHITECTURE_ID_X86 || ARCHITECTURE == ARCHITECTURE_ID_X64
    CheckX86CPUSupport();
#elif (defined(__aarch64__) || defined(__arm__))
    CheckARMSupport();
#elif (defined(__powerpc__))
    CheckPPCSupport();
#endif
    return true;
}

// Getter functions to check for a feature
bool
aesni_support()
{
    return aesni_support_;
}
bool
clmul_support()
{
    return clmul_support_;
}
bool
sha_support()
{
    return sha_support_;
}
bool
avx_support()
{
    return avx_support_;
}
bool
avx2_support()
{
    return avx2_support_;
}
bool
ssse3_support()
{
    return ssse3_support_;
}
bool
sse4_1_support()
{
    return sse4_1_support_;
}
bool
sse4_2_support()
{
    return sse4_2_support_;
}
bool
arm_neon_support()
{
    return arm_neon_support_;
}
bool
arm_aes_support()
{
    return arm_aes_support_;
}
bool
arm_pmull_support()
{
    return arm_pmull_support_;
}
bool
arm_sha1_support()
{
    return arm_sha1_support_;
}
bool
arm_sha2_support()
{
    return arm_sha2_support_;
}
bool
ppc_crypto_support()
{
    return ppc_crypto_support_;
}
