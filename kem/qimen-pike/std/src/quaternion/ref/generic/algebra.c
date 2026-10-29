#include <quaternion.h>
#include "internal.h"

// Internal helper functions

// in internal.h:
// static inline void quat_alg_init_set_ui(quat_alg_t *alg, unsigned int p) {
//     ibz_t bp;
//     ibz_init(&bp);
//     ibz_set(&bp, p);
//     quat_alg_init_set(alg, &bp);
//     ibz_finalize(&bp);
// }

void
quat_alg_coord_add(quat_alg_coord_t *res, const quat_alg_coord_t *a, const quat_alg_coord_t *b)
{
    ibz_add(&((*res)[0]), &((*a)[0]), &((*b)[0]));
    ibz_add(&((*res)[1]), &((*a)[1]), &((*b)[1]));
    ibz_add(&((*res)[2]), &((*a)[2]), &((*b)[2]));
    ibz_add(&((*res)[3]), &((*a)[3]), &((*b)[3]));
}

void
quat_alg_coord_sub(quat_alg_coord_t *res, const quat_alg_coord_t *a, const quat_alg_coord_t *b)
{
    ibz_sub(&((*res)[0]), &((*a)[0]), &((*b)[0]));
    ibz_sub(&((*res)[1]), &((*a)[1]), &((*b)[1]));
    ibz_sub(&((*res)[2]), &((*a)[2]), &((*b)[2]));
    ibz_sub(&((*res)[3]), &((*a)[3]), &((*b)[3]));
}

void
quat_alg_equal_denom(quat_alg_elem_t *res_a,
                     quat_alg_elem_t *res_b,
                     const quat_alg_elem_t *a,
                     const quat_alg_elem_t *b)
{
    ibz_t gcd, r;
    ibz_init(&gcd);
    ibz_init(&r);
    ibz_gcd(&gcd, &(a->denom), &(b->denom));
    // temporarily set res_a.denom to a.denom/gcd, and res_b.denom to b.denom/gcd
    ibz_div(&(res_a->denom), &r, &(a->denom), &gcd);
    ibz_div(&(res_b->denom), &r, &(b->denom), &gcd);
    for (int i = 0; i < 4; i++) {
        // multiply coordiates by reduced denominators from the other element
        ibz_mul(&(res_a->coord[i]), &(a->coord[i]), &(res_b->denom));
        ibz_mul(&(res_b->coord[i]), &(b->coord[i]), &(res_a->denom));
    }
    // multiply both reduced denominators
    ibz_mul(&(res_a->denom), &(res_a->denom), &(res_b->denom));
    // multiply them by the gcd to get the new common denominator
    ibz_mul(&(res_b->denom), &(res_a->denom), &gcd);
    ibz_mul(&(res_a->denom), &(res_a->denom), &gcd);
    ibz_finalize(&gcd);
    ibz_finalize(&r);
}

// Public Functions

void
quat_alg_add(quat_alg_elem_t *res, const quat_alg_elem_t *a, const quat_alg_elem_t *b)
{
    quat_alg_elem_t res_a, res_b;
    quat_alg_elem_init(&res_a);
    quat_alg_elem_init(&res_b);
    // put both on the same denominator
    quat_alg_equal_denom(&res_a, &res_b, a, b);
    // then add
    ibz_copy(&(res->denom), &(res_a.denom));
    quat_alg_coord_add(&(res->coord), &(res_a.coord), &(res_b.coord));
    quat_alg_elem_finalize(&res_a);
    quat_alg_elem_finalize(&res_b);
}

void
quat_alg_sub(quat_alg_elem_t *res, const quat_alg_elem_t *a, const quat_alg_elem_t *b)
{
    quat_alg_elem_t res_a, res_b;
    quat_alg_elem_init(&res_a);
    quat_alg_elem_init(&res_b);
    // put both on the same denominator
    quat_alg_equal_denom(&res_a, &res_b, a, b);
    // then substract
    ibz_copy(&res->denom, &res_a.denom);
    quat_alg_coord_sub(&res->coord, &res_a.coord, &res_b.coord);
    quat_alg_elem_finalize(&res_a);
    quat_alg_elem_finalize(&res_b);
}

void
quat_alg_mul(quat_alg_elem_t *res,
             const quat_alg_elem_t *a,
             const quat_alg_elem_t *b,
             const quat_alg_t *alg)
{
    ibz_t prod;
    quat_alg_coord_t sum;
    ibz_init(&prod);
    quat_alg_coord_init(&sum);

    ibz_set(&(sum[0]), 0);
    ibz_set(&(sum[1]), 0);
    ibz_set(&(sum[2]), 0);
    ibz_set(&(sum[3]), 0);

    // denominator: product of denominators
    ibz_mul(&(res->denom), &(a->denom), &(b->denom));

    // compute 1 coordinate
    ibz_mul(&prod, &(a->coord[2]), &(b->coord[2]));
    ibz_sub(&(sum[0]), &(sum[0]), &prod);
    ibz_mul(&prod, &(a->coord[3]), &(b->coord[3]));
    ibz_sub(&(sum[0]), &(sum[0]), &prod);
    ibz_mul(&(sum[0]), &(sum[0]), &(alg->p));
    ibz_mul(&prod, &(a->coord[0]), &(b->coord[0]));
    ibz_add(&(sum[0]), &(sum[0]), &prod);
    ibz_mul(&prod, &(a->coord[1]), &(b->coord[1]));
    ibz_sub(&(sum[0]), &(sum[0]), &prod);
    // compute i coordiante
    ibz_mul(&prod, &(a->coord[2]), &(b->coord[3]));
    ibz_add(&(sum[1]), &(sum[1]), &prod);
    ibz_mul(&prod, &(a->coord[3]), &(b->coord[2]));
    ibz_sub(&(sum[1]), &(sum[1]), &prod);
    ibz_mul(&(sum[1]), &(sum[1]), &(alg->p));
    ibz_mul(&prod, &(a->coord[0]), &(b->coord[1]));
    ibz_add(&(sum[1]), &(sum[1]), &prod);
    ibz_mul(&prod, &(a->coord[1]), &(b->coord[0]));
    ibz_add(&(sum[1]), &(sum[1]), &prod);
    // compute j coordiante
    ibz_mul(&prod, &(a->coord[0]), &(b->coord[2]));
    ibz_add(&(sum[2]), &(sum[2]), &prod);
    ibz_mul(&prod, &(a->coord[2]), &(b->coord[0]));
    ibz_add(&(sum[2]), &(sum[2]), &prod);
    ibz_mul(&prod, &(a->coord[1]), &(b->coord[3]));
    ibz_sub(&(sum[2]), &(sum[2]), &prod);
    ibz_mul(&prod, &(a->coord[3]), &(b->coord[1]));
    ibz_add(&(sum[2]), &(sum[2]), &prod);
    // compute ij coordiante
    ibz_mul(&prod, &(a->coord[0]), &(b->coord[3]));
    ibz_add(&(sum[3]), &(sum[3]), &prod);
    ibz_mul(&prod, &(a->coord[3]), &(b->coord[0]));
    ibz_add(&(sum[3]), &(sum[3]), &prod);
    ibz_mul(&prod, &(a->coord[2]), &(b->coord[1]));
    ibz_sub(&(sum[3]), &(sum[3]), &prod);
    ibz_mul(&prod, &(a->coord[1]), &(b->coord[2]));
    ibz_add(&(sum[3]), &(sum[3]), &prod);

    ibz_copy(&(res->coord[0]), &(sum[0]));
    ibz_copy(&(res->coord[1]), &(sum[1]));
    ibz_copy(&(res->coord[2]), &(sum[2]));
    ibz_copy(&(res->coord[3]), &(sum[3]));

    ibz_finalize(&prod);
    quat_alg_coord_finalize(&sum);
}

void
quat_alg_rightmul_mat(ibz_mat_4x4_t *mulmat, const quat_alg_elem_t *a, const quat_alg_t *alg)
{
    quat_alg_elem_t e, res;
    quat_alg_elem_init(&e);
    quat_alg_elem_init(&res);
    for (int i = 0; i < 4; i++) {
        // i-th standard basis vector
        if (i)
            ibz_set(&e.coord[i - 1], 0);
        ibz_set(&e.coord[i], 1);
        quat_alg_mul(&res, &e, a, alg);
        for (int j = 0; j < 4; j++)
            ibz_copy(&(*mulmat)[j][i], &res.coord[j]);
    }
    quat_alg_elem_finalize(&e);
    quat_alg_elem_finalize(&res);
}

void
quat_alg_norm(ibq_t *res, const quat_alg_elem_t *a, const quat_alg_t *alg)
{
    quat_alg_elem_t conj, norm;
    quat_alg_elem_init(&conj);
    quat_alg_elem_init(&norm);

    quat_alg_conj(&conj, a);
    quat_alg_mul(&norm, a, &conj, alg);
    ibq_set(res, &(norm.coord[0]), &(norm.denom));

    quat_alg_elem_finalize(&conj);
    quat_alg_elem_finalize(&norm);
}

void
quat_alg_trace(ibq_t *res, const quat_alg_elem_t *a)
{
    quat_alg_elem_t trace;
    quat_alg_elem_init(&trace);

    ibz_copy(&(trace.denom), &(a->denom));
    ibz_add(&(trace.coord[0]), &(a->coord[0]), &(a->coord[0]));
    ibz_sub(&(trace.coord[1]), &(a->coord[1]), &(a->coord[1]));
    ibz_sub(&(trace.coord[2]), &(a->coord[2]), &(a->coord[2]));
    ibz_sub(&(trace.coord[3]), &(a->coord[3]), &(a->coord[3]));
    ibq_set(res, &(trace.coord[0]), &(trace.denom));

    quat_alg_elem_finalize(&trace);
}

void
quat_alg_scalar(quat_alg_elem_t *elem, const ibz_t *numerator, const ibz_t *denominator)
{
    ibz_copy(&(elem->denom), denominator);
    ibz_copy(&(elem->coord[0]), numerator);
    ibz_set(&(elem->coord[1]), 0);
    ibz_set(&(elem->coord[2]), 0);
    ibz_set(&(elem->coord[3]), 0);
}

void
quat_alg_conj(quat_alg_elem_t *conj, const quat_alg_elem_t *x)
{
    ibz_copy(&(conj->denom), &(x->denom));
    ibz_copy(&(conj->coord[0]), &(x->coord[0]));
    ibz_neg(&(conj->coord[1]), &(x->coord[1]));
    ibz_neg(&(conj->coord[2]), &(x->coord[2]));
    ibz_neg(&(conj->coord[3]), &(x->coord[3]));
}

// defined in header
// int quat_alg_is_primitive(const quat_alg_elem_t *x, const quat_order_t *order, const quat_alg_t
// *alg) {
//   quat_alg_coord_t *coord;
//   quat_alg_coord_init(coord);
//   int ok = quat_lattice_contains(coord, order, x);
// assert(ok);
// unused(ok);
//  ibz_t *cnt;
//  ibz_init(cnt);
//  ibz_content(cnt, coord);
//  ok = ibz_is_one(cnt);
//  ibz_finalize(cnt);
//  quat_alg_coord_finalize(coord);
//  return ok;
//}
//
// static inline void quat_alg_make_primitive(quat_alg_coord_t *primitive_x, ibz_t *content, const
// quat_alg_elem_t *x, const quat_order_t *order, const quat_alg_t *alg){
//  int ok = quat_lattice_contains(primitive_x, order, x);
// assert(ok);
// unused(ok);
//  ibz_content(content, primitive_x);
//  for(int i = 0; i <4; i++){
//    ibz_div(primitive_x[i], NULL, primitive_x[i], content);
//  }
//}

void
quat_alg_normalize(quat_alg_elem_t *x)
{
    ibz_t gcd, r, zero;
    ibz_init(&gcd);
    ibz_init(&r);
    ibz_init(&zero);
    ibz_content(&gcd, &(x->coord));
    ibz_gcd(&gcd, &gcd, &(x->denom));
    ibz_div(&(x->denom), &r, &(x->denom), &gcd);
    for (int i = 0; i < 4; i++) {
        ibz_div(&(x->coord[i]), &r, &(x->coord[i]), &gcd);
    }
    ibz_set(&zero, 0);
    if (0 < ibz_cmp(&zero, &(x->denom))) {
        for (int i = 0; i < 4; i++) {
            ibz_neg(&(x->coord[i]), &(x->coord[i]));
        }
        ibz_neg(&(x->denom), &(x->denom));
    }
    ibz_finalize(&gcd);
    ibz_finalize(&r);
    ibz_finalize(&zero);
}

int
quat_alg_elem_is_zero(const quat_alg_elem_t *x)
{
    int res = quat_alg_coord_is_zero(&(x->coord));
    return (res);
}

int
quat_alg_coord_is_zero(const quat_alg_coord_t *x)
{
    int res = 1;
    for (int i = 0; i < 4; i++) {
        res &= ibz_is_zero(&((*x)[i]));
    }
    return (res);
}

// helper functions for lattices
void
quat_alg_elem_copy_ibz(quat_alg_elem_t *elem,
                       const ibz_t *denom,
                       const ibz_t *coord0,
                       const ibz_t *coord1,
                       const ibz_t *coord2,
                       const ibz_t *coord3)
{
    ibz_copy(&(elem->coord[0]), coord0);
    ibz_copy(&(elem->coord[1]), coord1);
    ibz_copy(&(elem->coord[2]), coord2);
    ibz_copy(&(elem->coord[3]), coord3);

    ibz_copy(&(elem->denom), denom);
}

void
quat_alg_elem_set(quat_alg_elem_t *elem,
                  int64_t denom,
                  int64_t coord0,
                  int64_t coord1,
                  int64_t coord2,
                  int64_t coord3)
{
    ibz_set(&(elem->coord[0]), coord0);
    ibz_set(&(elem->coord[1]), coord1);
    ibz_set(&(elem->coord[2]), coord2);
    ibz_set(&(elem->coord[3]), coord3);

    ibz_set(&(elem->denom), denom);
}

void
quat_alg_elem_mul_by_scalar(quat_alg_elem_t *res, const ibz_t *scalar, const quat_alg_elem_t *elem)
{
    for (int i = 0; i < 4; i++) {
        ibz_mul(&(res->coord[i]), &(elem->coord[i]), scalar);
    }
    ibz_copy(&(res->denom), &(elem->denom));
}

// FIXME : only works when p=3 mod 4
//  transpose the 1,i,j,k basis of an element of O0 the special maximal order, to coefficients in
//  the basis of O0
void
from_1ijk_to_O0basis(ibz_vec_4_t *vec, const quat_alg_elem_t *el)
{
    ibz_t tmp;
    ibz_init(&tmp);
    ibz_copy(&(*vec)[2], &el->coord[2]);
    ibz_add(&(*vec)[2], &(*vec)[2], &(*vec)[2]); // double (not optimal if el->denom is even...)
    ibz_copy(&(*vec)[3], &el->coord[3]);         // double (not optimal if el->denom is even...)
    ibz_add(&(*vec)[3], &(*vec)[3], &(*vec)[3]);
    ibz_sub(&(*vec)[0], &el->coord[0], &el->coord[3]);
    ibz_sub(&(*vec)[1], &el->coord[1], &el->coord[2]);

    if (!ibz_is_one(&el->denom)) {
        assert(ibz_divides(&(*vec)[0], &el->denom));
        assert(ibz_divides(&(*vec)[1], &el->denom));
        assert(ibz_divides(&(*vec)[2], &el->denom));
        assert(ibz_divides(&(*vec)[3], &el->denom));

        ibz_div(&(*vec)[0], &tmp, &(*vec)[0], &el->denom);
        ibz_div(&(*vec)[1], &tmp, &(*vec)[1], &el->denom);
        ibz_div(&(*vec)[2], &tmp, &(*vec)[2], &el->denom);
        ibz_div(&(*vec)[3], &tmp, &(*vec)[3], &el->denom);

        // ibz_div_2exp(&(*vec)[0], &(*vec)[0], 1);
        // ibz_div_2exp(&(*vec)[1], &(*vec)[1], 1);
    }
    ibz_finalize(&tmp);
}