#include <stdbool.h>
#include <stdio.h>

#include <sys/sysctl.h>
#include <sys/types.h>

static bool _neon = false;

bool
Hacl_has_aes()
{
  // NEON implies AES
  // - vaeseq_u8
  // - vaesdq_u8
  // - vaesmcq_u8
  // - vaesimcq_u8
  return _neon;
}

bool
Hacl_has_sha1()
{
  // NEON implies SHA1
  // - vsha1cq_u32
  // - vsha1pq_u32
  // - vsha1mq_u32
  // - vsha1h_u32
  // - vsha1su0q_u32
  // - vsha1su1q_u32
  return _neon;
}

bool
Hacl_has_sha2()
{
  // NEON implies SHA2
  // - vsha256hq_u32
  // - vsha256h2q_u32
  // - vsha256su0q_u32
  // - vsha256su1q_u32
  // - vsha512hq_u64
  // - vsha512h2q_u64
  // - vsha512su0q_u64
  // - vsha512su1q_u64
  return _neon;
}

bool
Hacl_init_macos_aarch64()
{
  int64_t ret = 0;
  size_t size = sizeof(ret);

  if (sysctlbyname("hw.optional.neon", &ret, &size, NULL, 0) == -1) {
    printf("Error retrieving macOS aarch64 hardware feature");
    return false;
  }
  _neon = ret == 1;

  return true;
}
