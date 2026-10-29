#include "reduce.h"
#include "params.h"


//reduce from [-2^15 *PARAM_Q,2^15*PARAM_Q] to (-PARAM_Q,PARAM_Q) 
int16_t montgomery_reduce(int32_t a)
{
	int16_t t;
	t = (int16_t)a * QINV;
	t = (a - (int32_t)t * PARAM_Q) >> 16;
	return t;
}
//reduce from [-9*PARAM_Q,9*PARAM_Q] to (-PARAM_Q,PARAM_Q)  Q = 3329
//reduce from [-51*PARAM_Q,51*PARAM_Q] to (-PARAM_Q,PARAM_Q)  Q = 641
int16_t barrett_reduce(int16_t a)
{
	int16_t u;
#if PARAM_Q == 3329
	u = ((int32_t)a * 9 + (1 << 14)) >> 15;
#elif PARAM_Q == 641
	u = ((int32_t)a * 51 + (1 << 14)) >> 15;
#endif
	u *= PARAM_Q;
	a -= u;
	return a;
}
//conditinonal add PARAM_Q
//reduce from [-PARAM_Q,PARAM_Q) to [0,PARAM_Q)
int16_t caddq (int16_t x)
{
	int16_t r;
	r = x + ((x >> 15)& PARAM_Q);
	return r;
}
//reduce from [-2*PARAM_Q,PARAM_Q) to [0,PARAM_Q)
int16_t caddq2(int16_t x)
{
	int16_t r;
	r = x + ((x >> 15)& PARAM_Q);
	r = r + ((r >> 15)& PARAM_Q);
	return r;
}
