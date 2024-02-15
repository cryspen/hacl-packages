#pragma once

#include "eurydice_glue.h"
#include "libcrux_kyber.h"

extern K___uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t__uint8_t_840size_t_
libcrux_digest_shake128x4f(size_t len,
                           Eurydice_slice input0,
                           Eurydice_slice input1,
                           Eurydice_slice input2,
                           Eurydice_slice input3);

#define libcrux_digest_shake128x4(len, input0, input1, input2, input3, _)      \
  libcrux_digest_shake128x4f(len, input0, input1, input2, input3)
