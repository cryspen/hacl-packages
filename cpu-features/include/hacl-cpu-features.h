/**
 * @brief CPU feature detection for HACL
 *
 * @file hacl-cpu-features.h
 * @author Franziskus Kiefer (franziskus@cryspen.com)
 * @brief
 * @version 0.1
 * @date 2022-02-13
 *
 * @copyright Copyright (c) 2022
 *
 */


#ifndef __Hacl_cpu_features_H
#define __Hacl_cpu_features_H

#if defined(__cplusplus)
extern "C" {
#endif

void
hacl_init_cpu_features();

unsigned int
hacl_vec128_support();

unsigned int
hacl_vec256_support();

unsigned int
vale_aesgcm_support();

unsigned int
vale_x25519_support();

unsigned int
vale_sha2_support();

#if defined(__cplusplus)
}
#endif

#endif // __Hacl_cpu_features_H
