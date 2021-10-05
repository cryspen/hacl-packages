#include "libintvector.h"

int main () {
  uint8_t block[32] = { 0 };
  Lib_IntVector_Intrinsics_vec128 b1 = Lib_IntVector_Intrinsics_vec128_load32_le(block);
  Lib_IntVector_Intrinsics_vec128 b2 = Lib_IntVector_Intrinsics_vec128_load32_le(block + 16);
  Lib_IntVector_Intrinsics_vec128 test = Lib_IntVector_Intrinsics_vec128_interleave_high64(b1, b2);
  return 0;
}
