#include "libintvector.h"

int main () {
  uint8_t block[64] = { 0 };
  Lib_IntVector_Intrinsics_vec256 b1 = Lib_IntVector_Intrinsics_vec256_load32_le(block);
  Lib_IntVector_Intrinsics_vec256 b2 = Lib_IntVector_Intrinsics_vec256_load32_le(block + 32);
  Lib_IntVector_Intrinsics_vec256 test = Lib_IntVector_Intrinsics_vec256_interleave_high64(b1, b2);
  return 0;
}
