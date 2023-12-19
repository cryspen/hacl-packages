#pragma once

#include "eurydice_glue.h"

typedef struct
  __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__s
{
  uint8_t fst[840U];
  uint8_t snd[840U];
  uint8_t thd[840U];
  uint8_t f3[840U];
} __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_;

extern void
libcrux_digest_shake256f(size_t len, Eurydice_slice input, uint8_t* out);

#define libcrux_digest_shake256(len, input, out, _)                            \
  libcrux_digest_shake256f(len, input, out)

extern void
libcrux_digest_shake128f(size_t len, Eurydice_slice input, uint8_t* out);

#define libcrux_digest_shake128(len, input, out, _)                            \
  libcrux_digest_shake128f(len, input, out)

extern __uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_
libcrux_digest_shake128x4f(size_t len,
                           Eurydice_slice input0,
                           Eurydice_slice input1,
                           Eurydice_slice input2,
                           Eurydice_slice input3);

#define libcrux_digest_shake128x4(len, input0, input1, input2, input3, _)      \
  libcrux_digest_shake128x4f(len, input0, input1, input2, input3)
