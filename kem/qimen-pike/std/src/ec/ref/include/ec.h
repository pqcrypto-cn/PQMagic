/** @file
 *
 * @authors Luca De Feo, Francisco RH
 *
 * @brief Elliptic curve stuff
 */

#ifndef EC_H
#define EC_H

#include <fp2.h>
#include <ec_params.h>
#include <tools.h>
#include <stdio.h>

/** @defgroup ec Elliptic curves
 * @{
 */

/** @defgroup ec_t Data structures
 * @{
 */

/** @brief Projective point
 *
 * @typedef ec_point_t
 *
 * @struct ec_point_t
 *
 * A projective point in (X:Z) or (X:Y:Z) coordinates (tbd).
 */
typedef struct ec_point_t
{
    fp2_t x;
    fp2_t z;
} ec_point_t;

/** @brief Projective point
 *
 * @typedef jac_point_t
 *
 * @struct jac_point_t
 *
 * A projective point in(X:Y:Z) coordinates
 */
typedef struct jac_point_t
{
    fp2_t x;
    fp2_t y;
    fp2_t z;
} jac_point_t;

/** @brief A basis of a torsion subgroup
 *
 * @typedef ec_basis_t
 *
 * @struct ec_basis_t
 *
 * A pair of points (or a triplet, tbd) forming a basis of a torsion subgroup.
 */
typedef struct ec_basis_t
{
    ec_point_t P;
    ec_point_t Q;
    ec_point_t PmQ;
} ec_basis_t;

/** @brief An elliptic curve
 *
 * @typedef ec_curve_t
 *
 * @struct ec_curve_t
 *
 * An elliptic curve in projective Montgomery form
 */
typedef struct ec_curve_t
{
    fp2_t A;
    fp2_t C;                             ///< cannot be 0
    ec_point_t A24;                      // the point (A+2 : 4C)
    bool is_A24_computed_and_normalized; // says if A24 has been computed and normalized
} ec_curve_t;

/** @brief An isogeny of degree a power of 2
 *
 * @typedef ec_isog_even_t
 *
 * @struct ec_isog_even_t
 */
typedef struct ec_isog_even_t
{
    ec_curve_t curve;      ///< The domain curve
    ec_point_t kernel;     ///< A kernel generator
    unsigned short length; ///< The length as a 2-isogeny walk
} ec_isog_even_t;

/** @brief An odd divisor of p² - 1
 *
 * @typedef ec_isog_odd_t
 *
 * Given that the list of divisors of p² - 1 is known, this is
 * represented as a fixed-length vector of integer exponents.
 */

typedef uint16_t ec_degree_odd_t[P_LEN + M_LEN]; // For NGCC_2, we must use uint16 instead of uint8..

/** @brief An isogeny of odd degree dividing p² - 1
 *
 * @typedef ec_isog_odd_t
 *
 * @struct ec_isog_odd_t
 */
typedef struct ec_isog_odd_t
{
    ec_curve_t curve;
    ec_point_t ker_plus;    ///< A generator of E[p+1] ∩ ker(φ)
    ec_point_t ker_minus;   ///< A generator of E[p-1] ∩ ker(φ)
    ec_degree_odd_t degree; ///< The degree of the isogeny
} ec_isog_odd_t;

/** @brief Isomorphism of Montgomery curves
 *
 * @typedef ec_isom_t
 *
 * @struct ec_isom_t
 *
 * The isomorphism is given by the map maps (X:Z) ↦ ( (Nx X - Nz Z) : (D Z) )
 */
typedef struct ec_isom_t
{
    fp2_t Nx;
    fp2_t Nz;
    fp2_t D;
} ec_isom_t;

// end ec_t
/** @}
 */

/** @defgroup ec_curve_t Curves and isomorphisms
 * @{
 */

void ec_curve_init(ec_curve_t *E);
void ec_curve_normalize_A24(ec_curve_t *E);

/**
 * @brief Isomorphism of elliptic curve
 *
 * @param isom computed isomorphism
 * @param from domain curve
 * @param to image curve
 */
void ec_isomorphism(ec_isom_t *isom, const ec_curve_t *from, const ec_curve_t *to);

/**
 * @brief In-place inversion of an isomorphism
 *
 * @param isom an isomorphism
 */
void ec_iso_inv(ec_isom_t *isom);

/**
 * @brief In-place evaluation of an isomorphism
 *
 * @param P a point
 * @param isom an isomorphism
 */
void ec_iso_eval(ec_point_t *P, ec_isom_t *isom);

/** @}
 */
/** @defgroup ec_point_t Point operations
 * @{
 */

/**
 * @brief Point equality
 *
 * @param P a point
 * @param Q a point
 * @return 1 if equal
 */
bool ec_is_equal(const ec_point_t *P, const ec_point_t *Q);

/**
 * @brief Reduce Z-coordinate of point in place
 *
 * @param P a point
 */
void ec_normalize_point(ec_point_t *P);

/**
 * @brief Test whether a point is on a curve
 *
 * @param curve a curve
 * @param P a point
 * @return 1 if P is on the curve
 */
int ec_is_on_curve(const ec_curve_t *curve, const ec_point_t *P);

/**
 * @brief Point negation
 *
 * @param res computed opposite of P
 * @param P a point
 */
void ec_neg(ec_point_t *res, const ec_point_t *P);

/**
 * @brief Point addition
 *
 * @param res computed sum of P and Q
 * @param P a point
 * @param Q a point
 * @param PQ the difference P-Q
 */
void ec_add(ec_point_t *res, const ec_point_t *P, const ec_point_t *Q, const ec_point_t *PQ);

/**
 * @brief Point doubling
 *
 * @param res computed double of P
 * @param P a point
 */
void ec_dbl(ec_point_t *res, const ec_curve_t *curve, const ec_point_t *P);

/**
 * @brief Point multiplication
 *
 * @param res computed scalar * P
 * @param curve the curve
 * @param scalar an unsigned multi-precision integer
 * @param P a point
 */
void ec_mul(ec_point_t *res, const ec_curve_t *curve, const digit_t *scalar, const int size, const ec_point_t *P);

/**
 * @brief Point multiplication by a scalar of limited length
 *
 * @param res computed scalar * P
 * @param curve the curve
 * @param scalar an unsigned multi-precision integer
 * @param kbits the bit size of scalar
 * @param P a point
 */
void xMULv2(ec_point_t *Q,
            ec_point_t const *P,
            digit_t const *k,
            const int kbits,
            ec_point_t const *A24);

/**
 * @brief Combination P+m*Q
 *
 * @param R computed P + m * Q
 * @param curve the curve
 * @param m an unsigned multi-precision integer
 * @param P a point
 * @param Q a point
 * @param PQ the difference P-Q
 */
void ec_ladder3pt_bounded(ec_point_t *R,
                          digit_t *const m,
                          ec_point_t const *P,
                          ec_point_t const *Q,
                          ec_point_t const *PQ,
                          ec_curve_t const *A,
                          int size);

/**
 * @brief Linear combination of points of a basis
 *
 * @param res computed scalarP * P + scalarQ * Q
 * @param curve the curve
 * @param scalarP an unsigned multi-precision integer
 * @param scalarQ an unsigned multi-precision integer
 * @param PQ a torsion basis consisting of points P and Q
 */
void ec_biscalar_mul(ec_point_t *res,
                     const ec_curve_t *curve,
                     const digit_t *scalarP,
                     const digit_t *scalarQ,
                     const ec_basis_t *PQ);

// same as above but points are expected to have order 2^f
void ec_biscalar_mul_bounded(ec_point_t *res,
                             const ec_curve_t *curve,
                             const digit_t *scalarP,
                             const digit_t *scalarQ,
                             const ec_basis_t *PQ,
                             int size);

void difference_point(ec_point_t *PQ, const ec_point_t *P, const ec_point_t *Q, const ec_curve_t *curve);

/** @defgroup ec_dlog_t Discrete logs and bases
 * @{
 */

/**
 * @brief Generate a Montgomery curve and a 2^f-torsion basis
 *
 * The algorithm is deterministc
 *
 * @param PQ2 computed basis of the 2^f-torsion
 * @param curve the computed curve
 */
void ec_curve_to_basis_2(ec_basis_t *PQ2, ec_curve_t *curve, int f);

void ec_curve_to_basis_2_to_hint(ec_basis_t *PQ2, ec_curve_t *curve, int f, int *hint);

void ec_curve_to_basis_2_from_hint(ec_basis_t *PQ2, ec_curve_t *curve, int f, int *hint);

void ec_curve_to_basis_2f(ec_basis_t *PQ2, ec_curve_t *curve, int f);
void ec_curve_to_basis_2f_to_hint(ec_basis_t *PQ2, ec_curve_t *curve, int f, int *hint);
void ec_curve_to_basis_2f_from_hint(ec_basis_t *PQ2, ec_curve_t *curve, int f, int *hint);
void ec_complete_basis_2f(ec_basis_t *PQ2, ec_curve_t *curve, const ec_point_t *R, int f);

/**
 * @brief Complete a basis of the 2^f-torsion
 *
 * The algorithm is deterministic
 *
 * @param PQ2 a basis of the 2^f-torsion containing P as first generator
 * @param curve the curve
 * @param P a point of order 2^f
 */
void ec_complete_basis_2(ec_basis_t *PQ2, const ec_curve_t *curve, const ec_point_t *P);

/**
 * @brief Generate a pls-torsion basis
 *
 * The algorithm is deterministic
 *
 * @param PQpls the computed pls-torsion basis
 * @param curve a curve
 */
void ec_curve_to_basis_pls(ec_basis_t *PQpls, const ec_curve_t *curve, const uint64_t *PRIMES, const int size);

void ec_curve_to_basis_pls_from_hint(ec_basis_t *PQpls, const ec_curve_t *curve, const uint64_t *PRIMES, const int size, int *hint);

void ec_curve_to_basis_pls_to_hint(ec_basis_t *PQpls, const ec_curve_t *curve, const uint64_t *PRIMES, const int size, int *hint);

/**
 * @brief Generate a Tmin-torsion basis
 *
 * The algorithm is deterministic
 *
 * @param PQTmin the computed Tmin-torsion basis
 * @param curve a curve
 */
void ec_curve_to_basis_Tmin(ec_basis_t *PQTmin, const ec_curve_t *curve, const uint64_t *PRIMES, const int size);

void ec_curve_to_basis_Tmin_to_hint(ec_basis_t *PQTmin, const ec_curve_t *curve, const uint64_t *PRIMES, const int size, int *hint);

void ec_curve_to_basis_Tmin_from_hint(ec_basis_t *PQTmin, const ec_curve_t *curve, const uint64_t *PRIMES, const int size, int *hint);

/**
 * @brief Compute the generalized dlog of R wrt the 2^f-basis PQ2
 *
 * Ensure that R = scalarP * P + scalarQ * Q
 *
 * @param scalarP the computed dlog
 * @param scalarQ the computed dlog
 * @param PQ2 a 2^f-torsion basis
 * @param R a point of order dividing 2^f
 */
void ec_dlog_2(digit_t *scalarP,
               digit_t *scalarQ,
               const ec_basis_t *PQ2,
               const ec_point_t *R,
               const ec_curve_t *curve);

/** @}
 */

/** @defgroup ec_isog_t Isogenies
 * @{
 */
/**
 * @brief Evaluate isogeny of odd degree on list of points
 *
 * @param image computed image curve
 * @param phi isogeny
 * @param points a list of points to evaluate the isogeny on, modified in place
 * @param length of the list points
 */
void ec_eval_odd(ec_curve_t *image,
                 const ec_isog_odd_t *phi,
                 ec_point_t *points,
                 unsigned short length);

/**
 * @brief Evaluate isogeny of odd degree on list of torsion bases
 *
 * @param image computed image curve
 * @param phi isogeny
 * @param points a list of bases to evaluate the isogeny on, modified in place
 * @param length of the list bases
 */
static inline void
ec_eval_odd_basis(ec_curve_t *image,
                  const ec_isog_odd_t *phi,
                  ec_basis_t *points,
                  unsigned short length)
{
    ec_eval_odd(image, phi, (ec_point_t *)points, sizeof(ec_basis_t) / sizeof(ec_point_t) * length);
}

void copy_jac_point(jac_point_t *P, jac_point_t const *Q);
bool is_jac_equal(const jac_point_t *P, const jac_point_t *Q);
void jac_neg(jac_point_t *Q, jac_point_t const *P);
void jac_to_xz(ec_point_t *P, const jac_point_t *xyP);
bool is_jac_xz_equal(const jac_point_t *P, const ec_point_t *Q);
void ADD(jac_point_t *R, jac_point_t const *P, jac_point_t const *Q, ec_curve_t const *AC);
void DBL(jac_point_t *Q, jac_point_t const *P, ec_curve_t const *AC);
void recover_y(fp2_t *y, fp2_t const *Px, ec_curve_t const *curve);
void recover_domain(ec_curve_t *A, const ec_point_t *P, const ec_point_t *Q, const ec_point_t *PmQ);
void lift_point(jac_point_t *P, ec_point_t *Q, ec_curve_t *E);
void lift_basis(jac_point_t *P, jac_point_t *Q, ec_basis_t *B, ec_curve_t *E);

static int
test_point_order_twof(const ec_point_t *P, const ec_curve_t *E, int t)
{
    ec_point_t test;
    test = *P;
    // copy_point(&test,P);
    if (fp2_is_zero(&test.z))
        return 0;
    for (int i = 0; i < t - 1; i++)
    {
        ec_dbl(&test, E, &test);
    }
    if (fp2_is_zero(&test.z))
        return 0;
    ec_dbl(&test, E, &test);
    return (fp2_is_zero(&test.z));
}

static int
test_jac_order_twof(const jac_point_t *P, const ec_curve_t *E, int t)
{
    jac_point_t test;
    test = *P;
    if (fp2_is_zero(&test.z))
        return 0;
    for (int i = 0; i < t - 1; i++)
    {
        DBL(&test, &test, E);
    }
    if (fp2_is_zero(&test.z))
        return 0;
    DBL(&test, &test, E);
    return (fp2_is_zero(&test.z));
}

static void
point_print(char *name, ec_point_t P)
{
    fp2_t a;
    if (fp2_is_zero(&P.z))
    {
        printf("%s = INF\n", name);
    }
    else
    {
        fp2_copy(&a, &P.z);
        fp2_inv(&a);
        fp2_mul(&a, &a, &P.x);
        fp2_print(name, &a);
    }
}

static void
curve_print(char *name, ec_curve_t E)
{
    fp2_t a;
    fp2_copy(&a, &E.C);
    fp2_inv(&a);
    fp2_mul(&a, &a, &E.A);
    fp2_print(name, &a);
}

static inline void
AC_to_A24(ec_point_t *A24, ec_curve_t const *E)
{
    // A24 = (A+2C : 4C)
    fp2_add(&A24->z, &E->C, &E->C);
    fp2_add(&A24->x, &E->A, &A24->z);
    fp2_add(&A24->z, &A24->z, &A24->z);
}

static inline void
A24_to_AC(ec_curve_t *E, ec_point_t const *A24)
{
    // (A:C) = ((A+2C)*2-4C : 4C)
    fp2_add(&E->A, &A24->x, &A24->x);
    fp2_sub(&E->A, &E->A, &A24->z);
    fp2_add(&E->A, &E->A, &E->A);
    fp2_copy(&E->C, &A24->z);
}

void xDBL_A24_normalized(ec_point_t *Q, ec_point_t const *P, ec_point_t const *A24);

/** @}
 */

// end ec
/** @}
 */

#endif
