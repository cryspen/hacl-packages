#include "libintvector.h"

#if TARGET_ARCHITECTURE == TARGET_ARCHITECTURE_ID_X64
#include <stdint.h>
#endif

int
main()
{
  uint8_t block[32] = { 0 };
  Lib_IntVector_Intrinsics_vec128 b1 =
    Lib_IntVector_Intrinsics_vec128_load32_le(
      block); // SSE2 | NEON - A7, A32, A64
  Lib_IntVector_Intrinsics_vec128 b2 =
    Lib_IntVector_Intrinsics_vec128_load32_le(block +
                                              16); // SSE2 | NEON - A7, A32, A64
  Lib_IntVector_Intrinsics_vec128 test =
    Lib_IntVector_Intrinsics_vec128_interleave_high64(b1,
                                                      b2); // SSE2 | NEON A64
  Lib_IntVector_Intrinsics_vec128 eq = Lib_IntVector_Intrinsics_vec128_eq64(
    b1, b1); // SSE4.1 | NEON - A7, A32, A64
  Lib_IntVector_Intrinsics_vec128 gt = Lib_IntVector_Intrinsics_vec128_eq64(
    b1, b2); // SSE4.2 | NEON - A7, A32, A64

  Lib_IntVector_Intrinsics_vec128 rotated =
    Lib_IntVector_Intrinsics_vec128_rotate_left32(
      test, (uint32_t)7U); // SSE3 | NEON - A7, A32, A64
  return 0;
}
