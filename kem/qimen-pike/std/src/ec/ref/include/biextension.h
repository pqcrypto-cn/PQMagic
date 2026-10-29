#ifndef _BIEXT_H_
#define _BIEXT_H_

#include <fp2.h>
#include "ec.h"

void A24_from_AC(ec_point_t *A24, ec_point_t const *AC);

void weil(fp2_t *r, int e, ec_point_t *P, ec_point_t *Q, ec_point_t *PQ, ec_point_t *A24);

void non_reduced_tate(fp2_t *r,
                      uint64_t e,
                      ec_point_t *P,
                      ec_point_t *Q,
                      ec_point_t *PQ,
                      ec_point_t *A24);

void tate_odd_TORSION_D(fp2_t *r, uint64_t *n, ec_point_t *P, ec_point_t *Q, ec_point_t *PQ, ec_point_t *A24);

void tate_odd_Tmin(fp2_t *r, uint64_t *n, ec_point_t *P, ec_point_t *Q, ec_point_t *PQ, ec_point_t *A24);

void ec_dlog_2_weil_single(digit_t *scalarP2,
                           digit_t *scalarQ2,
                           ec_basis_t *PQ,
                           ec_point_t *point,
                           ec_curve_t *curve,
                           int e);

void ec_dlog_Tmin_tate(digit_t *scalarP1,
                       digit_t *scalarQ1,
                       digit_t *scalarP2,
                       digit_t *scalarQ2,
                       ec_basis_t *PQ,
                       ec_basis_t *basis,
                       ec_curve_t *curve);

void ec_dlog_Tpls_tate_single(digit_t *scalarP2,
                              digit_t *scalarQ2,
                              ec_basis_t *PQ,
                              ec_point_t *point,
                              ec_curve_t *curve);

void fp2_dlog_2e(digit_t *scal, const fp2_t *f, const fp2_t *g, int e);
#endif
