/* 
  This file was generated by KaRaMeL <https://github.com/FStarLang/karamel>
  KaRaMeL invocation: /Users/jonathan/Code/eurydice/eurydice ../libcrux_kyber.llbc
  F* version: 71f2d632
  KaRaMeL version: 8e0595bd
 */

#ifndef __Eurydice_H
#define __Eurydice_H

#include "eurydice_glue.h"

typedef struct core_ops_range_Range__size_t_s
{
  size_t start;
  size_t end;
}
core_ops_range_Range__size_t;

typedef size_t core_ops_range_RangeTo__size_t;

typedef size_t core_ops_range_RangeFrom__size_t;

extern uint8_t Eurydice_bitand_pv_u8(uint8_t *x, uint8_t y);

extern uint8_t Eurydice_shr_pv_u8(uint8_t *x, int32_t y);


#define __Eurydice_H_DEFINED
#endif
