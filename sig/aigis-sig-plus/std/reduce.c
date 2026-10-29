#include <stdint.h>
#include "params.h"
#include "reduce.h"


//Output t is smaller than PARAM_Q in absolute value. 
int32_t montgomery_reduce(int64_t a) 
{
	int32_t t;
	t = (int32_t)a*QINV;
	t = (a - (int64_t)t*PARAM_Q) >> 32;
	return t;
}
//Output t is smaller than PARAM_Q in absolute value.
int32_t barrat_reduce(int32_t a) //works if |a|<460138740 > 110* Q
{
	int32_t t;
	t = (a + (1 << 21)) >> 22;
	t *= PARAM_Q;
	t =a - t;
	return t;
}

int32_t general_reduce(int32_t a) //works if -2^31 < a < 2^31
{
	int32_t t = ((int64_t)a * 2159079753)>> 53;
	t *= PARAM_Q;
	return a - t;
}

//computing r = a mod PARAM_Q for |a| < PARAM_Q such that 0 <= r < PARAM_Q
int32_t amodq(int32_t a)
{
	a += (a >> 31) & PARAM_Q;
	return a;
}
//computing r = a mod PARAM_Q for |a| < PARAM_Q such that -PARAM_Q/2 < r <= PARAM_Q/2
int32_t cmodq(int32_t a)
{
	int32_t t;
	a += (a >> 31) & PARAM_Q;
	t = PARAM_Q / 2 - a;
	a -= (t >> 31) & PARAM_Q;
	return a;
}