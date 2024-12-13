#include <stdint.h>
#include "params.h"
#include "reduce.h"

uint32_t montgomery_reduce(uint64_t a) {
  const uint64_t qinv = QINV;
  uint64_t t;

  t = a * qinv;
  t &= (1ULL << 32) - 1;
  t *= PARAM_Q;
  t += a;
  return t >> 32;
}

uint32_t barrat_reduce(uint32_t a) {
  uint32_t t;

#if PARAM_Q == 2021377 //works if a < 55943712 > 27 *Q
  t = a>> 21;
  t *= PARAM_Q;
  a -= t;
#elif PARAM_Q == 3870721  //works if a < 50172538 > 12* Q
      t = a >> 22;
      t *= PARAM_Q;
      a -= t;
#endif 
  return a;
}

uint32_t freeze2q(uint32_t a)
{
    a -= PARAM_Q;
    a += ((int32_t)a >> 31) & PARAM_Q;
    return a;
}

uint32_t freeze4q(uint32_t a)
{
    a -= 2*PARAM_Q;
    a += ((int32_t)a >> 31) & (2*PARAM_Q);
    a -= PARAM_Q;
    a += ((int32_t)a >> 31) & PARAM_Q;
    return a;
}
