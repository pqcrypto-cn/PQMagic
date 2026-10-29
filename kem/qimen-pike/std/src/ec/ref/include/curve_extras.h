#ifndef CURVE_EXTRAS_H
#define CURVE_EXTRAS_H

#include "ec.h"
#include "torsion_constants.h"

bool ec_is_zero(ec_point_t const *P);
void ec_set_zero(ec_point_t *P);
void copy_curve(ec_curve_t *E1, ec_curve_t const *E2);
void copy_point(ec_point_t *P, ec_point_t const *Q);
void swap_points(ec_point_t *P, ec_point_t *Q, const digit_t option);
void ec_point_init(ec_point_t *P);
void ec_curve_init(ec_curve_t *E);
void xDBL_A24(ec_point_t *Q, ec_point_t const *P, ec_point_t const *A24);
void xDBLADD(ec_point_t *R,
             ec_point_t *S,
             ec_point_t const *P,
             ec_point_t const *Q,
             ec_point_t const *PQ,
             ec_point_t const *A24);
void xDBL(ec_point_t *Q, ec_point_t const *P, ec_point_t const *AC);
void xMUL(ec_point_t *Q, ec_point_t const *P, digit_t const *k, const int size, ec_curve_t const *curve);
void xDBLMUL(ec_point_t *S,
             ec_point_t const *P,
             digit_t const *k,
             ec_point_t const *Q,
             digit_t const *l,
             ec_point_t const *PQ,
             const ec_curve_t *curve);

void
xDBLMUL_bounded(ec_point_t *S,
                ec_point_t const *P,
                digit_t const *k,
                ec_point_t const *Q,
                digit_t const *l,
                ec_point_t const *PQ,
                const ec_curve_t *curve,
                int f);

#define is_point_equal ec_is_equal
#define xADD ec_add

#endif
