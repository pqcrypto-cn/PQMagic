#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "params.h"

#if PARAM_Q == 2021377
#define MONT 1562548U // 2^32 % Q
#define QINV 2849953791U // -q^(-1) mod 2^32

#elif PARAM_Q == 3870721
#define MONT 2337707U // 2^32 % Q
#define QINV 2671448063U // -q^(-1) mod 2^32

#endif


/* a <= Q*2^32 = > r < 2*Q */
#define montgomery_reduce AIGIS_SIG_NAMESPACE(montgomery_reduce)
uint32_t montgomery_reduce(uint64_t a);

/* a<12*Q, r < 2*Q */
#define barrat_reduce AIGIS_SIG_NAMESPACE(barrat_reduce)
uint32_t barrat_reduce(uint32_t a);

/* a<2*Q, r < Q */
#define freeze2q AIGIS_SIG_NAMESPACE(freeze2q)
uint32_t freeze2q(uint32_t a);
/* a<4*Q, r < Q */
#define freeze4q AIGIS_SIG_NAMESPACE(freeze4q)
uint32_t freeze4q(uint32_t a);
#endif
