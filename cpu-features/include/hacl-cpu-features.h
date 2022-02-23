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

#ifndef __Hacl_cpu_features_H
#define __Hacl_cpu_features_H

#if defined(__cplusplus)
extern "C"
{
#endif

  void hacl_init_cpu_features();

  unsigned int hacl_vec128_support();

  unsigned int hacl_vec256_support();

  unsigned int vale_aesgcm_support();

  unsigned int vale_x25519_support();

  unsigned int vale_sha2_support();

#if defined(__cplusplus)
}
#endif

#endif // __Hacl_cpu_features_H
