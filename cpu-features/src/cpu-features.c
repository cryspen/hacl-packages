/*
 * https://www.intel.com/content/dam/develop/external/us/en/documents/architecture-instruction-set-extensions-programming-reference-806695.pdf
 *
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
 */

#include "hacl-cpu-features.h"
#include "internal_state.h"

#if defined(i386) || defined(__i386) || defined(__X86__) || defined(_M_IX86)
#define CPU_FEATURES_X86
#elif defined(__x86_64__) || defined(__x86_64) || defined(_M_AMD64)
#define CPU_FEATURES_X64
#elif defined(__arm64__) || defined(__arm64) || defined(__aarch64__)
#define CPU_FEATURES_ARM64
#elif defined(__s390x__)
#define CPU_FEATURES_S390X
#else
#error "Unsupported CPU"
#endif

#if defined(__APPLE__) || defined(__APPLE_CC__)
#include <sys/sysctl.h>
#include <sys/types.h>
#define CPU_FEATURES_MACOS
#elif defined(__linux__)
#define CPU_FEATURES_LINUX
#elif defined(_WIN32)
#define CPU_FEATURES_WINDOWS
#else
#error "Unsupported OS"
#endif

#if defined(CPU_FEATURES_WINDOWS)
#if defined(_MSC_VER)
#include <intrin.h>
#define CPU_FEATURES_MSVC
#else
#define CPU_FEATURES_NON_MSVC
#endif
#endif

#if defined(CPU_FEATURES_LINUX) && defined(CPU_FEATURES_ARM64) &&  \
  defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 16)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#define GETAUXVAL_FUNC
#ifndef HWCAP_ASIMD
#define HWCAP_ASIMD (1 << 1)
#endif
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1 << 6)
#endif
#endif
#endif

// === x86 | x64

#if (defined(CPU_FEATURES_LINUX) || defined(CPU_FEATURES_MACOS) ||     \
  defined(CPU_FEATURES_NON_MSVC)) && defined(CPU_FEATURES_X64)
void
cpuid(unsigned long leaf,
      unsigned long* eax,
      unsigned long* ebx,
      unsigned long* ecx,
      unsigned long* edx)
{
  __asm__("xor %%ecx, %%ecx\n\t"
          "cpuid\n\t"
          : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
          : "0"(leaf));
}

#elif (defined(CPU_FEATURES_LINUX) || defined(CPU_FEATURES_NON_MSVC)) &&   \
  defined(CPU_FEATURES_X86)
/* XXX: Find a 32-bit CPU to actually test this */
void
cpuid(unsigned long leaf,
      unsigned long* eax,
      unsigned long* ebx,
      unsigned long* ecx,
      unsigned long* edx)
{
  __asm__("xor %%ecx, %%ecx\n\t"
          "mov %%ebx,%%edi\n\t"
          "cpuid\n\t"
          "xchgl %%ebx,%%edi\n\t"
          : "=a"(*eax), "=D"(*ebx), "=c"(*ecx), "=d"(*edx)
          : "0"(leaf));
}
#endif

// ECX
#define ECX_SSE3 (1 << 0)
#define ECX_PCLMUL (1 << 1)
#define ECX_SSSE3 (1 << 9)
#define ECX_FMA (1 << 12)
#define ECX_SSE4_1 (1 << 19)
#define ECX_SSE4_2 (1 << 20)
#define ECX_MOVBE (1 << 22)
#define ECX_AESNI (1 << 25)
#define ECX_AVX (1 << 28)

// EBX
#define EBX_BMI1 (1 << 3)
#define EBX_AVX2 (1 << 5)
#define EBX_BMI2 (1 << 8)
#define EBX_ADX (1 << 19)
#define EBX_SHA (1 << 29)

// EDX
#define EDX_SSE (1 << 25)
#define EDX_SSE2 (1 << 26)
#define EDX_CMOV (1 << 15)

// === End x86 | x64

// === MacOS ARM

// === End MacOS ARM

// Static feature variables
static unsigned int _adx = 0;
static unsigned int _aes = 0;
static unsigned int _sha = 0;
static unsigned int _avx = 0;
static unsigned int _avx2 = 0;
static unsigned int _sse = 0;
static unsigned int _sse2 = 0;
static unsigned int _sse3 = 0;
static unsigned int _ssse3 = 0;
static unsigned int _sse41 = 0;
static unsigned int _sse42 = 0;
static unsigned int _bmi1 = 0;
static unsigned int _bmi2 = 0;
static unsigned int _pclmul = 0;
static unsigned int _movbe = 0;
static unsigned int _cmov = 0;
// AArch64-specific variables
static unsigned int _asimd = 0;

// API

unsigned int
hacl_vec128_support()
{
#if defined(CPU_FEATURES_X64) || defined(CPU_FEATURES_X86)
  return _sse && _sse2 && _sse3 && _sse41 && _sse41 && _cmov;
#elif defined(CPU_FEATURES_ARM64)
  return _asimd;
#elif defined(CPU_FEATURES_S390X)
  return 1;
#else
  return 0;
#endif
}

unsigned int
hacl_vec256_support()
{
  return _avx && _avx2;
}

unsigned int
hacl_aesgcm_support()
{
  return hacl_vec128_support() && _aes && _pclmul;
}

unsigned int
vale_aesgcm_support()
{
  return _aes && _pclmul && _avx && _sse && _movbe;
}

unsigned int
vale_x25519_support()
{
  return _bmi2 && _adx;
}

unsigned int
vale_sha2_support()
{
  return _sha && _sse;
}

void
hacl_init_cpu_features()
{
#if (defined(CPU_FEATURES_X64) || defined(CPU_FEATURES_X86)) &&         \
  (defined(CPU_FEATURES_LINUX) || defined(CPU_FEATURES_MACOS) ||        \
  defined(CPU_FEATURES_WINDOWS))
  unsigned long eax, ebx, ecx, edx, eax_sub, ebx_sub, ecx_sub, edx_sub;
#if defined(CPU_FEATURES_MSVC)
  int cpu_info[4];
  int cpu_info_sub[4];
  __cpuidex(cpu_info, 1, 0);
  __cpuidex(cpu_info_sub, 7, 0);
  eax = cpu_info[0];
  ebx = cpu_info[1];
  ecx = cpu_info[2];
  edx = cpu_info[3];
  eax_sub = cpu_info_sub[0];
  ebx_sub = cpu_info_sub[1];
  ecx_sub = cpu_info_sub[2];
  edx_sub = cpu_info_sub[3];
#else
  cpuid(1, &eax, &ebx, &ecx, &edx);
  cpuid(7, &eax_sub, &ebx_sub, &ecx_sub, &edx_sub);
#endif

  _aes = (ecx & ECX_AESNI) != 0;
  _avx = (ecx & ECX_AVX) != 0;
  _pclmul = (ecx & ECX_PCLMUL) != 0;
  _movbe = (ecx & ECX_MOVBE) != 0;

  _avx2 = (ebx_sub & EBX_AVX2) != 0;
  _bmi1 = (ebx_sub & EBX_BMI1) != 0;
  _bmi2 = (ebx_sub & EBX_BMI2) != 0;
  _adx = (ebx_sub & EBX_ADX) != 0;
  _sha = (ebx_sub & EBX_SHA) != 0;

  _sse = (edx & EDX_SSE) != 0;
  _sse2 = (edx & EDX_SSE2) != 0;
  _cmov = (edx & EDX_CMOV) != 0;

  _sse3 = (ecx & ECX_SSE3) != 0;
  _ssse3 = (ecx & ECX_SSSE3) != 0;
  _sse41 = (ecx & ECX_SSE4_1) != 0;
  _sse42 = (ecx & ECX_SSE4_2) != 0;

#elif defined(CPU_FEATURES_LINUX) && defined(CPU_FEATURES_ARM64) &&    \
  defined(GETAUXVAL_FUNC)
  unsigned long hwcap = getauxval(AT_HWCAP);
  _asimd = ((hwcap & HWCAP_ASIMD) != 0) ? 1 : 0;
  _aes = ((hwcap & HWCAP_AES) != 0) ? 1 : 0;
  _pclmul = ((hwcap & HWCAP_PMULL) != 0) ? 1 : 0;
  _sha = ((hwcap & HWCAP_SHA2) != 0) ? 1 : 0;

#elif defined(CPU_FEATURES_MACOS) && defined(CPU_FEATURES_ARM64)
  int err;
  int64_t ret = 0;
  size_t size = sizeof(ret);

  err = sysctlbyname("hw.optional.AdvSIMD", &ret, &size, NULL, 0);
  _asimd = (err == 0 && ret > 0) ? 1 : 0;

  ret = 0;
  size = sizeof(ret);
  err = sysctlbyname("hw.optional.arm.FEAT_AES", &ret, &size, NULL, 0);
  _aes = (err == 0 && ret > 0) ? 1 : 0;

  ret = 0;
  size = sizeof(ret);
  err = sysctlbyname("hw.optional.arm.FEAT_PMULL", &ret, &size, NULL, 0);
  _pclmul = (err == 0 && ret > 0) ? 1 : 0;

  ret = 0;
  size = sizeof(ret);
  err = sysctlbyname("hw.optional.arm.FEAT_SHA256", &ret, &size, NULL, 0);
  _sha = (err == 0 && ret > 0) ? 1 : 0;
#endif
}

// CPU specific API
unsigned int
hacl_adx_support()
{
  return _adx;
}
unsigned int
hacl_aes_support()
{
  return _aes;
}
unsigned int
hacl_sha_support()
{
  return _sha;
}
unsigned int
hacl_avx_support()
{
  return _avx;
}
unsigned int
hacl_avx2_support()
{
  return _avx2;
}
unsigned int
hacl_sse_support()
{
  return _sse;
}
unsigned int
hacl_sse2_support()
{
  return _sse2;
}
unsigned int
hacl_sse3_support()
{
  return _sse3;
}
unsigned int
hacl_ssse3_support()
{
  return _ssse3;
}
unsigned int
hacl_sse41_support()
{
  return _sse41;
}
unsigned int
hacl_sse42_support()
{
  return _sse42;
}
unsigned int
hacl_bmi1_support()
{
  return _bmi1;
}
unsigned int
hacl_bmi2_support()
{
  return _bmi2;
}
unsigned int
hacl_pclmul_support()
{
  return _pclmul;
}
unsigned int
hacl_movbe_support()
{
  return _movbe;
}
unsigned int
hacl_cmov_support()
{
  return _cmov;
}
