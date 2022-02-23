/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <stdio.h>

#include "hacl-cpu-features.h"
#include "internal_state.h"

int
main()
{
  hacl_init_cpu_features();
  printf("\n\n ========== HACL Available CPU Features ==========\n");
  printf("\tAES \t%s supported\n", hacl_aes_support() ? "   " : "not");
  printf("\tAVX \t%s supported\n", hacl_avx_support() ? "   " : "not");
  printf("\tAVX2 \t%s supported\n", hacl_avx2_support() ? "   " : "not");
  printf("\tBMI1 \t%s supported\n", hacl_bmi1_support() ? "   " : "not");
  printf("\tBMI2 \t%s supported\n", hacl_bmi2_support() ? "   " : "not");
  printf("\tADX \t%s supported\n", hacl_adx_support() ? "   " : "not");
  printf("\tSHA \t%s supported\n", hacl_sha_support() ? "   " : "not");
  printf("\tSSE \t%s supported\n", hacl_sse_support() ? "   " : "not");
  printf("\tSSE2 \t%s supported\n", hacl_sse2_support() ? "   " : "not");
  printf("\tSSE3 \t%s supported\n", hacl_sse3_support() ? "   " : "not");
  printf("\tSSSE3 \t%s supported\n", hacl_ssse3_support() ? "   " : "not");
  printf("\tSSE4.1 \t%s supported\n", hacl_sse41_support() ? "   " : "not");
  printf("\tSSE4.2 \t%s supported\n", hacl_sse42_support() ? "   " : "not");
  printf(" ==================================================\n\n\n");

  printf("\n\n ========= HACL Available Implementations =========\n");
  printf("\tVec128 \t\t%s supported\n", hacl_vec128_support() ? "   " : "not");
  printf("\tVec256 \t\t%s supported\n", hacl_vec256_support() ? "   " : "not");
  printf("\tVale AES-GCM \t%s supported\n",
         vale_aesgcm_support() ? "   " : "not");
  printf("\tVace x25519 \t%s supported\n",
         vale_x25519_support() ? "   " : "not");
  printf("\tVace SHA2 \t%s supported\n", vale_sha2_support() ? "   " : "not");
  printf(" ==================================================\n\n\n");
}
