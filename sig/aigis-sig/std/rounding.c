#include <stdint.h>
#include "params.h"
#include "reduce.h"
#include "rounding.h"


uint32_t power2round(uint32_t a, uint32_t *a0)  {
  int32_t t;
  t = a & ((1 << PARAM_D) - 1);
  t -= (1 << (PARAM_D-1)) + 1;
  t += (t >> 31) & (1 << PARAM_D);
  t -= (1 << (PARAM_D-1)) - 1;
  *a0 = PARAM_Q + t;
  a = (a - t) >> PARAM_D;
  return a;
}

uint32_t decompose(uint32_t a, uint32_t *a0) 
{
#if (PARAM_Q-1) != 6*ALPHA
#error "decompose() assumes (PARAM_Q-1) == 6*ALPHA"
#endif

  int32_t t, u;
#if ALPHA == 336896

  u = ((a*3)>>20) + 1;//fast div by constant, works if a< 9323824 > 27*ALPHA
  t = a - u*ALPHA;
  u -= (t>>31)&0x1;
  t += (t >> 31) & ALPHA;

#elif ALPHA == 645120 

  u = ((a*3)>>21) + 1;//fast div by constant, works if a< 9323824 > 12*ALPHA
  t = a - u*ALPHA;
  u -= (t>>31)&0x1;
  t += (t >> 31) & ALPHA;

#endif

  t -= ALPHA/2 + 1;
  t += (t >> 31) & ALPHA;
  t -= ALPHA/2 - 1;
  
  a = u + ((t>>31)&0x1);

  if(a == 6)
  {
	  *a0 = PARAM_Q + t - 1;
	  a = 0;
  }
  else
	  *a0 = PARAM_Q + t;

  return a;
}

unsigned int make_hint(const uint32_t a, const uint32_t b) {
  uint32_t t;
  return decompose(a, &t) != decompose(freeze4q(a + b), &t);
}

uint32_t use_hint(const uint32_t a, const unsigned int hint) {
  uint32_t a0, a1;
  
  a1 = decompose(a, &a0);
  if(hint == 0)
    return a1;
  else if(a0 > PARAM_Q)
    return (a1 == (PARAM_Q - 1)/ALPHA - 1) ? 0 : a1 + 1;
  else
    return (a1 == 0) ? (PARAM_Q - 1)/ALPHA - 1 : a1 - 1;
}
