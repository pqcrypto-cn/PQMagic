#include <stdint.h>
#include "params.h"
#include "reduce.h"


int32_t power2round(int32_t a, int32_t *a0)  
{
  int32_t a1;
  a1 = (a + (1 << (PARAM_D - 1)) - 1) >> PARAM_D;
  *a0 = a - (a1 << PARAM_D);
  return a1;
}

//please input 0<a<PARAM_Q
// int32_t decompose(int32_t a, int32_t *a0)
// {
// 	int32_t a1;
// 	a1 = (a + ALPHA/2 - 1) / ALPHA;//ensure that -ALPHA/2 <*a0 <= -ALPHA/2
// 	if (a1 == (PARAM_Q - 1) / ALPHA)
// 	{
// 		a1 = 0;
// 		*a0 = a - PARAM_Q;
// 	}
// 	else
// 		*a0 = a - a1 * ALPHA;
// 	return a1;
// }

int32_t decompose(int32_t a, int32_t *a0)
{
	int32_t a1;

#if ALPHA == 695296

	/*
	 * ALPHA = 695296 = 128 * 5432
	 * (PARAM_Q - 1) / ALPHA = 6
	 */
	a1 = (a + 127) >> 7;
	a1 = (a1 * 6177 + (1 << 24)) >> 25;
	a1 ^= ((5 - a1) >> 31) & a1;

#elif ALPHA == 1042944

	/*
	 * ALPHA = 1042944 = 128 * 8148
	 * (PARAM_Q - 1) / ALPHA = 4
	 */
	a1 = (a + 127) >> 7;
	a1 = (a1 * 2059 + (1 << 23)) >> 24;
	a1 ^= ((3 - a1) >> 31) & a1;

#elif ALPHA == 347648

	/*
	 * ALPHA = 347648 = 128 * 2716
	 * (PARAM_Q - 1) / ALPHA = 12
	 */
	a1 = (a + 127) >> 7;
	a1 = (a1 * 6177 + (1 << 23)) >> 24;
	a1 ^= ((11 - a1) >> 31) & a1;

#elif ALPHA == 86912

	/*
	 * ALPHA = 86912 = 64 * 1358
	 * 注意：不能用 (a + 127) >> 7，
	 * 因为 86912 / 128 = 679 为奇数，128 分块不再安全。
	 *
	 * (PARAM_Q - 1) / ALPHA = 48
	 */
	a1 = (a + 63) >> 6;
	a1 = (a1 * 24709 + 16752312) >> 25;
	a1 ^= ((47 - a1) >> 31) & a1;

#else
#error "Unsupported ALPHA"
#endif

	*a0 = a - a1 * ALPHA;
	*a0 -= (((PARAM_Q - 1) / 2 - *a0) >> 31) & PARAM_Q;

	return a1;
}

unsigned int make_hint(const int32_t a, const int32_t b) {
  if(a <= GAMMA2 || a > PARAM_Q - GAMMA2 || (a == PARAM_Q - GAMMA2 && b == 0))
	  return 0;
  return 1;
}

int32_t use_hint(const int32_t a, const int32_t hint) {
	int32_t a0, a1;

	a1 = decompose(a, &a0);
	if (hint == 0)
		return a1;

#if (PARAM_Q - 1)/ALPHA == 4
	if (a0 > 0)
		//return (a1 == (PARAM_Q - 1)/ALPHA - 1) ? 0 : a1 + 1;
		return (a1 + 1) & 0x3;
	else
		return (a1 - 1) & 0x3;
	//return (a1 == 0) ? (PARAM_Q - 1)/ALPHA - 1 : a1 - 1;
#else
	if (a0 > 0)
		return (a1 == (PARAM_Q - 1) / ALPHA - 1) ? 0 : a1 + 1;
	else
		return (a1 == 0) ? (PARAM_Q - 1) / ALPHA - 1 : a1 - 1;
#endif
}
