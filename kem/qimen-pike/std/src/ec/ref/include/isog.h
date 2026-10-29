#ifndef _ISOG_H_
#define _ISOG_H_

#include <ec.h>
#include "curve_extras.h"

/* KPS structure for isogenies of degree 2 or 4 */
typedef struct
{
    ec_point_t K;
} ec_kps2_t;
typedef struct
{
    ec_point_t K[3];
} ec_kps4_t;

/* Cursed global constant for odd degree isogenies */
extern ec_point_t K[83]; // Finite subsets of the kernel

void kps_t(uint64_t const i, ec_point_t const P, ec_point_t const A); // tvelu formulae
void xisog_t(ec_point_t *B, uint64_t const i, ec_point_t const A); // tvelu formulae
void xeval_t(ec_point_t *Q, uint64_t const i, ec_point_t const P); // tvelu formulae

// hybrid velu formulae
static inline void
kps(uint64_t const i, ec_point_t const P, ec_point_t const A)
{
    kps_t(i, P, A);
}

static inline void
xisog(ec_point_t *B, uint64_t const i, ec_point_t const A)
{
    xisog_t(B, i, A);
}

static inline void
xeval(ec_point_t *Q, uint64_t const i, ec_point_t const P, ec_point_t const A)
{
    xeval_t(Q, i, P);
}

#endif
