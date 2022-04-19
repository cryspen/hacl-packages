/*
 *    Copyright 2022 Cryspen Sarl
 *
 *    Licensed under the Apache License, Version 2.0 or MIT.
 *    - http://www.apache.org/licenses/LICENSE-2.0
 *    - http://opensource.org/licenses/MIT
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
