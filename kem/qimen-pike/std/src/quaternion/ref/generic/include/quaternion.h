/** @file
 *
 * @authors Luca De Feo, Sina Schaeffler
 *
 * @brief Declarations for quaternion algebra operations
 */

#ifndef QUATERNION_H
#define QUATERNION_H

// #include <rng.h>
#include <intbig.h>
#include <assert.h>

#define QUATERNION_lideal_generator_search_bound 1024

/** @defgroup quat_quat Quaternion algebra
 * @{
 */

/** @defgroup quat_vec_t Types for integer vectors and matrices
 * @{
 */

/** @brief Type for vectors of 4 integers
 *
 * @typedef ibz_vec_4_t
 *
 * Represented as a vector of 4 ibz_t (big integer) elements
 */
typedef ibz_t ibz_vec_4_t[4];

/** @brief Type for vectors of 5 integers
 *
 * @typedef ibz_vec_5_t
 *
 * Represented as a vector of 5 ibz_t (big integer) elements
 */
typedef ibz_t ibz_vec_5_t[5];

/** @brief Type for 2 by 2 matrices of integers
 *
 * @typedef ibz_mat_2x2_t
 *
 * Represented as a matrix of 2 vectors of 2 ibz_t (big integer) elements
 */
typedef ibz_t ibz_mat_2x2_t[2][2];

/** @brief Type for 4 by 4 matrices of integers
 *
 * @typedef ibz_mat_4x4_t
 *
 * Represented as a matrix of 4 vectors of 4 ibz_t (big integer) elements
 */
typedef ibz_t ibz_mat_4x4_t[4][4];

/** @brief Type for 4 by 5 matrices of integers
 *
 * @typedef ibz_mat_4x5_t
 *
 * Represented as a matrix of 4 vectors of 5 ibz_t (big integer) elements
 */
typedef ibz_t ibz_mat_4x5_t[4][5];

/** @brief Type for 4 by 8 matrices of integers
 *
 * @typedef ibz_mat_4x8_t
 *
 * Consists in and 4 by 8 matrix of ibz_t (big integers)
 */
typedef ibz_t ibz_mat_4x8_t[4][8];
/**
 * @}
 */

/** @defgroup quat_quat_t Types for quaternion algebras
 * @{
 */

/** @brief Type for quaternion algebras
 *
 * @typedef quat_alg_t
 *
 * @struct quat_alg
 *
 * The quaternion algebra ramified at p = 3 mod 4 and ∞.
 */
typedef struct quat_alg
{
    ibz_t p;            ///< Prime number, must be = 3 mod 4.
    ibz_mat_4x4_t gram; ///< Gram matrix of the norm form
} quat_alg_t;

/** @brief Type for integer coordinates in a basis
 *
 * @typedef quat_alg_coord_t
 *
 * Represented as a vector of 4 ibz_t (big integer) elements
 */
typedef ibz_vec_4_t quat_alg_coord_t;

/** @brief Type for quaternion algebra elements
 *
 * @typedef quat_alg_elem_t
 *
 * @struct quat_alg_elem
 *
 * Represented as a array *coord* of 4 ibz_t integers and a common ibz_t denominator *denom*.
 *
 * The representation is not necessarily normalized, that is, gcd(denom, content(coord)) might not
 * be 1. For getting a normalized representation, use the quat_alg_normalize function
 *
 * The elements are always represented in basis (1,i,j,ij) of the quaternion algebra, with i^2=-1
 * and j^2 = -p
 */
typedef struct quat_alg_elem
{
    ibz_t denom; ///< Denominator by which all coordinates are divided (big integer, must not be 0)
    quat_alg_coord_t coord; ///< Numerators of the 4 coordinates of the quaternion algebra element
                            ///< in basis (1,i,j,ij)
} quat_alg_elem_t;

/** @brief Type for lattices in dimension 4
 *
 * @typedef quat_lattice_t
 *
 * @struct quat_lattice
 *
 * Represented as a rational (`frac`) times an integreal lattice (`basis`)
 *
 * The basis is in hermite normal form, and its columns divided by its denominator are elements of
 * the quaternion algebra, represented in basis (1,i,j,ij) where i^2 = -1, j^2 = -p.
 *
 * All lattices must have full rank (4)
 */
typedef struct quat_lattice
{
    ibz_t denom;         ///< Denominator by which the basis is divided (big integer, must not be 0)
    ibz_mat_4x4_t basis; ///< Integer basis of the lattice in hermite normal form (its columns
                         ///< divided by denom are algebra elements in the usual basis)
} quat_lattice_t;

/** @brief Type for quaternion orders
 *
 * @typedef quat_order_t
 *
 * Internally represented as a quat_lattice_t.
 *
 *  That means that the basis is in hermite normal form, and its columns divided by its denominator
 * are elements of the quaternion algebra, represented in basis (1,i,j,ij) where i^2 = -1, j^2 = -p.
 */
typedef quat_lattice_t quat_order_t;

/** @brief Type for left ideals in quaternion algebras
 *
 * @typedef quat_left_ideal_t
 *
 * @struct quat_left_ideal
 *
 * The basis of the lattice representing it is in hermite normal form, and its columns divided by
 * its denominator are elements of the quaternion algebra, represented in basis (1,i,j,ij) where i^2
 * = -1, j^2 = -p.
 */
typedef struct quat_left_ideal
{
    quat_lattice_t lattice;           ///< lattice representing the ideal
    ibz_t norm;                       ///< norm of the lattice
    const quat_order_t *parent_order; ///< should be a maximal ideal
} quat_left_ideal_t;
/** @}
 */

/** @brief Type for extremal maximal orders
 *
 * @typedef quat_p_extremal_maximal_order_t
 *
 * @struct quat_p_extremal_maximal_order
 *
 * The basis of the order representing it is in hermite normal form, and its columns divid
ed by its denominator are elements of the quaternion algebra, represented in basis (1,i,j,
ij) where i^2 = -q, j^2 = -p.
*/
typedef struct quat_p_extremal_maximal_order
{
    quat_order_t order; ///< the order represented as a lattice
    quat_alg_elem_t i;  ///< the element of small discriminant
    quat_alg_elem_t j;  ///< the element of norm p orthogonal to i
    int64_t q;          ///< the absolute value of sqrt of i
} quat_p_extremal_maximal_order_t;

/*************************** Functions *****************************/

/** @defgroup quat_c Constructors and Destructors
 * @{
 */
void quat_alg_init_set(quat_alg_t *alg, const ibz_t *p);
void quat_alg_finalize(quat_alg_t *alg);

void quat_alg_elem_init(quat_alg_elem_t *elem);
void quat_alg_elem_finalize(quat_alg_elem_t *elem);

void quat_alg_coord_init(quat_alg_coord_t *coord);
void quat_alg_coord_finalize(quat_alg_coord_t *coord);

void ibz_vec_4_init(ibz_vec_4_t *vec);
void ibz_vec_4_finalize(ibz_vec_4_t *vec);

void ibz_vec_5_init(ibz_vec_5_t *vec);
void ibz_vec_5_finalize(ibz_vec_5_t *vec);

void ibz_mat_2x2_init(ibz_mat_2x2_t *mat);
void ibz_mat_2x2_finalize(ibz_mat_2x2_t *mat);

void ibz_mat_4x4_init(ibz_mat_4x4_t *mat);
void ibz_mat_4x4_finalize(ibz_mat_4x4_t *mat);

void ibz_mat_4x5_init(ibz_mat_4x5_t *mat);
void ibz_mat_4x5_finalize(ibz_mat_4x5_t *mat);

void ibz_mat_4x8_init(ibz_mat_4x8_t *mat);
void ibz_mat_4x8_finalize(ibz_mat_4x8_t *mat);

/** @brief initiazlize matrix with arbitrary dimensions
 */
void ibz_mat_init(int rows, int cols, ibz_t mat[rows][cols]);
/** @brief finalize matrix with arbitrary dimensions
 */
void ibz_mat_finalize(int rows, int cols, ibz_t mat[rows][cols]);

void quat_lattice_init(quat_lattice_t *lat);
void quat_lattice_finalize(quat_lattice_t *lat);

void quat_order_init(quat_order_t *order);
void quat_order_finalize(quat_order_t *order);

void quat_left_ideal_init(quat_left_ideal_t *lideal);
void quat_left_ideal_finalize(quat_left_ideal_t *lideal);
/** @}
 */

/** @defgroup quat_printers Print functions for types from the quaternion module
 * @{
 */
void ibz_mat_2x2_print(const ibz_mat_2x2_t *mat);
void ibz_mat_4x4_print(const ibz_mat_4x4_t *mat);
void ibz_mat_4x5_print(const ibz_mat_4x5_t *mat);
void ibz_mat_4x8_print(const ibz_mat_4x8_t *mat);
void ibz_mat_print(int rows, int cols, const ibz_t mat[rows][cols]);
void ibz_vec_2_print(const ibz_vec_2_t *vec);
void ibz_vec_4_print(const ibz_vec_4_t *vec);
void ibz_vec_5_print(const ibz_vec_5_t *vec);

void quat_lattice_print(const quat_lattice_t *lat);
void quat_alg_print(const quat_alg_t *alg);
void quat_alg_elem_print(const quat_alg_elem_t *elem);
void quat_alg_coord_print(const quat_alg_coord_t *coord);
void quat_order_print(const quat_order_t *order);
void quat_left_ideal_print(const quat_left_ideal_t *lideal);

/** @}
 */

/** @defgroup quat_int Integer functions for quaternion algebra
 * @{
 */

/** @defgroup quat_int_mat Integer matrix and vector functions
 * @{
 */

/** @brief Set matrix coefficients to the given integers
 *
 * @param mat Output: Matrix
 * @param a00
 * @param a01
 * @param a10
 * @param a11
 */
void ibz_mat_2x2_set(ibz_mat_2x2_t *mat, int a00, int a01, int a10, int a11);

/** @brief mat*vec in dimension 2 for integers
 *
 * @param res Output vector
 * @param mat Input vector
 * @param vec Input vector
 */
void ibz_mat_2x2_eval(ibz_vec_2_t *res, const ibz_mat_2x2_t *mat, const ibz_vec_2_t *vec);

/**
 * @brief a*b for 2x2 integer matrices modulo m
 *
 * @param prod Output matrix
 * @param mat_a Input matrix
 * @param mat_b Input matrix
 * @param m Integer modulo
 */
void ibz_2x2_mul_mod(ibz_mat_2x2_t *prod,
                     const ibz_mat_2x2_t *mat_a,
                     const ibz_mat_2x2_t *mat_b,
                     const ibz_t *m);

/**
 * @brief Inverse of 2x2 integer matrices modulo m
 *
 * @param inv Output matrix
 * @param mat Input matrix
 * @param m Integer modulo
 * @return 1 if inverse exists 0 otherwise
 */
void ibz_mat_2x2_add(ibz_mat_2x2_t *sum, const ibz_mat_2x2_t *mat_a, const ibz_mat_2x2_t *mat_b);

int ibz_2x2_inv_mod(ibz_mat_2x2_t *inv, const ibz_mat_2x2_t *mat, const ibz_t *m);

void ibz_mat_2x2_copy(ibz_mat_2x2_t *new, const ibz_mat_2x2_t *mat);

void ibz_mat_4x4_copy(ibz_mat_4x4_t *new, const ibz_mat_4x4_t *mat);

void ibz_vec_4_set(ibz_vec_4_t *vec,
                   int64_t coord0,
                   int64_t coord1,
                   int64_t coord2,
                   int64_t coord3);

void ibz_mat_4x4_transpose(ibz_mat_4x4_t *transposed, const ibz_mat_4x4_t *mat);
void ibz_mat_4x4_mul(ibz_mat_4x4_t *res, const ibz_mat_4x4_t *a, const ibz_mat_4x4_t *b);
int ibz_mat_4x4_scalar_div(ibz_mat_4x4_t *quot, const ibz_t *scalar, const ibz_mat_4x4_t *mat);
void ibz_mat_4x4_scalar_mul(ibz_mat_4x4_t *prod, const ibz_t *scalar, const ibz_mat_4x4_t *mat);

/**
 * @brief mat*vec
 *
 *
 * @param res Output: coordinate vector
 * @param mat Integer 4x4 matrix
 * @param vec Integer vector (coordinate vector)
 *
 * Multiplies 4x4 integer matrix mat by a 4-integers vector vec
 */
void ibz_mat_4x4_eval(ibz_vec_4_t *res, const ibz_mat_4x4_t *mat, const ibz_vec_4_t *vec);

/**
 * @brief Computes modulo p the left kernel of mat where p is prime
 *
 * Algorithm used is the one at number 2.3.1 in Henri Cohen's "A Course in Computational Algebraic
 * Number Theory" (Springer Verlag, in series "Graduate texts in Mathematics") from 1993
 *
 * @param ker Output: a vector in kernel which is not 0 modulo p if exists, otherwise 0
 * @param mat A 4×5 matrix
 * @param p Integer modulo which the kernel computation is done, must be prime
 * @return 1 if a unique such vector was found, 0 otherwise
 *
 */
int ibz_4x5_right_ker_mod_prime(ibz_vec_5_t *ker, const ibz_mat_4x5_t *mat, const ibz_t *p);

/**
 * @brief Computes modulo p the left kernel of mat where p is prime
 *
 * Algorithm used is the one at number 2.3.1 in Henri Cohen's "A Course in Computational Algebraic
 * Number Theory" (Springer Verlag, in series "Graduate texts in Mathematics") from 1993
 *
 * @param ker Output: a vector in kernel which is not 0 modulo p if exists, otherwise 0
 * @param mat A 4×4 matrix
 * @param p Integer modulo which the kernel computation is done, must be prime
 * @return 1 if a unique such vector was found, 0 otherwise
 *
 */
int ibz_4x4_right_ker_mod_prime(ibz_vec_4_t *ker, const ibz_mat_4x4_t *mat, const ibz_t *p);

/**
 * @brief Computes the right kernel of mat modulo 2^exp
 *
 * @param ker Output: a vector in kernel which is not 0 modulo 2, if it exists, otherwise 0
 * @param mat A 4×4 matrix
 * @param exp exponent defining the modulus
 * @return 1 if a unique such vector was found, 0 otherwise
 *
 */
int ibz_4x4_right_ker_mod_power_of_2(ibz_vec_4_t *ker,
                                     const ibz_mat_4x4_t *mat,
                                     unsigned short exp);

/**
 * @brief content of a 4-vector of integers
 *
 * The content is the GCD of all entries.
 *
 * @param v A 4-vector of integers
 * @param content Output: the resulting gcd
 */
static inline void
ibz_content(ibz_t *content, const ibz_vec_4_t *v)
{
    ibz_gcd(content, &((*v)[0]), &((*v)[1]));
    ibz_gcd(content, &((*v)[2]), content);
    ibz_gcd(content, &((*v)[3]), content);
}

/** @}
 */

/** @defgroup quat_integer Integer functions for quaternion algebra
 * @{
 */

/**
 * @brief Find integers x and y such that x^2 + n*y^2 = p
 *
 * Uses Cornacchia's algorithm, should be used  only for prime p
 *
 * @param x Output
 * @param y Output
 * @param n first parameter defining the equation
 * @param p seond parameter defining the equation, must be prime
 * @return 1 if success, 0 otherwise
 */
int ibz_cornacchia_prime(ibz_t *x, ibz_t *y, const ibz_t *n, const ibz_t *p);

/**
 * @brief Solving cornacchia to find x² + n y³ = 2^exp_adjust * p in the special case of n=3 mod 4
 *
 * This function sometimes fails to find a solution even if one exists and all parameters are as
 * specified.
 *
 * @param x Output: an integer
 * @param y Output: an integer
 * @param n an integer
 * @param p a prime integer
 * @param exp_adjust an exponent, must be > 0
 * @returns 1 if success, 0 if failure to find a solution
 */
int ibz_cornacchia_special_prime(ibz_t *x,
                                 ibz_t *y,
                                 const ibz_t *n,
                                 const ibz_t *p,
                                 const int exp_adjust);

/**
 * @brief Find x and y such that x^2 + y^2 = n
 *
 * Uses "extended" version of Cornacchia's algorithm which also allows to solve x^2 + y^2 = n for
 * some composite numbers. This uses a prime factor decomposition of n via trial division for primes
 * in the list, computes solutions for n's prime factors and then uses complex multiplication. Since
 * (x+iz)(x-iy) = x^2 + y^2, so a solution xp,yp for p and xq,yq for q give a solution for pq by
 * computing (xp+iyp)*(xq+iyq).
 *
 * @param x Output
 * @param y Output
 * @param n parameter defining the equation. To get an output if one exists, only 1 of its prime
 * factors can exceed the largest prime in prime_list
 * @param prime_list list of consecutive primes starting from 2
 * @param prime_list_length number of elements of prime_list. Cans be smaller than that number, in
 * which case only the beginning of the list is used.
 * @param primality_test_iterations number of Miller-Rabin iterations to verify primality before
 * trying to compute a square root of 1 modulo the remaining number once all small primes were
 * factored out
 * @param bad_primes_prod Assumed to be a product of small primes which are 3 mod 4. Used only to
 * accelerate failure in case its gcd with n is not 1. Can be NULL
 * @return 1 if success, 0 otherwise
 */
int ibz_cornacchia_extended(ibz_t *x,
                            ibz_t *y,
                            const ibz_t *n,
                            const short *prime_list,
                            const int prime_list_length,
                            short primality_test_iterations,
                            const ibz_t *bad_primes_prod);

/** @}
 */

/** @defgroup quat_qf Quadratic form functions
 * @{
 */

/**
 * @brief Quadratic form evaluation
 *
 * qf and coord must be represented in the same basis.
 *
 * @param res Output: coordinate vector
 * @param qf Quadratic form (4x4 integer matrix)
 * @param coord Integer vector (coordinate vector)
 */
void quat_qf_eval(ibz_t *res, const ibz_mat_4x4_t *qf, const quat_alg_coord_t *coord);
/** @}
 */

/** @defgroup quat_lat_2x2 Functions for lattices in dimension 2
 * @{
 */

/**
 * @brief Find a lattice vector close to a target vector satisfying extra conditions.
 *
 * Given a target vector `target` = (x₀,y₀), enumerate vectors `v` = (x,y) in lattice `lat` with
 * distance (x₀ - x)² + `qf` (y₀ - y)² < 2^`dist_bound`. On each vector `condition(res, target - v,
 * params)` is called: if it returns a non-zero value, processing stops and the same value is
 * returned; if it returns 0 processing continues until `max_tries` vectors have been tried.
 *
 * The implementation will first reduce the basis by finding a short vector with algorithm 1.3.14
 * (Gauss) from Henri Cohen's "A Course in Computational Algebraic Number Theory" (Springer Verlag,
 * in series "Graduate texts in Mathematics") from 1993. Then a second one is added to this basis
 * after reduction by projection on the first one. A close vector is found using 2 projection as in
 * https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/cvp.pdf (15.5.2023,16h15CEST) using
 * the already reduced matrix Finally, short vectors are enumerated below an enumeration bound set
 * to (2 ^ dist_bound - (distance of target to close vector)). Each short vector is added to the
 * close vector, and then the distance to the target is measured. If it is below 2^dist_bound, it is
 * tested for condition. If coundition returns 1, the algorithm terminates and returns 1, otherwise
 * it returns 0 when max_tries vectors have been tried
 *
 * The enumeration bound is an heuristic to avoid starting the search with vectors which will be too
 * far from the target, since enumeration starts at the largest vectors. It can in some cases lead
 * to failures even though solutions do exist, an in other cases be insufficient to get a valid
 * result in reasonable time.
 *
 * Enumeration uses algorithm 2.7.5 (Fincke-Pohst) from Henri Cohen's "A Course in Computational
 * Algebraic Number Theory" (Springer Verlag, in series "Graduate texts in Mathematics") from 1993
 * Slightly adapted to work without rational numbers and their square roots
 * Therefore needing a test to make sure the bounds are respected, which is integrated in
 * quat_dim2_lattice_bound_and_condition
 *
 * @param res Output: quaternion element returned by `condition`
 * @param lat_basis basis of an integral 2-dimensional lattice
 * @param target target vector for CVP
 * @param qf Small integer defining a quadratic form x² + qf y²
 * @param dist_bound Log of the maximum distance between `target` and the enumerated vectors
 * @param condition Filter the vectors of `lat` by passing them to `condition`. When it returns a
 * non-zero value, the result is put into `res` and the processing stops.
 * @param params Extra parameters passed to `condition`. May be NULL.
 * @param max_tries Try at most `max_tries` vectors close to `target`
 * @return 1 if an element was found, 0 otherwise
 */
int quat_2x2_lattice_enumerate_cvp_filter(quat_alg_elem_t *res,
                                          const ibz_mat_2x2_t *lat_basis,
                                          const ibz_vec_2_t *target,
                                          unsigned int qf,
                                          unsigned int dist_bound,
                                          int (*condition)(quat_alg_elem_t *,
                                                           const ibz_vec_2_t *,
                                                           const void *),
                                          const void *params,
                                          unsigned int max_tries);

/** @}
 */
/** @}
 */

int quat_lattice_random_elem(quat_alg_elem_t *elem, const quat_lattice_t *lattice, unsigned char n);

/** @defgroup quat_quat_f Quaternion algebra functions
 * @{
 */
void quat_alg_add(quat_alg_elem_t *res, const quat_alg_elem_t *a, const quat_alg_elem_t *b);
void quat_alg_sub(quat_alg_elem_t *res, const quat_alg_elem_t *a, const quat_alg_elem_t *b);
void quat_alg_mul(quat_alg_elem_t *res,
                  const quat_alg_elem_t *a,
                  const quat_alg_elem_t *b,
                  const quat_alg_t *alg);

/** @brief reduced norm of alg_elem x
 *
 * @param res Output: rational which will contain the reduced norm of a
 * @param x Algebra element whose norm is computed
 * @param alg The quaternion algebra
 */
void quat_alg_norm(ibq_t *res, const quat_alg_elem_t *x, const quat_alg_t *alg);

/** @brief reduced trace of alg_elem x
 *
 * @param res Output: rational which will contain the reduced trace of a
 * @param x Algebra element whose trace will be computed
 */
void quat_alg_trace(ibq_t *res, const quat_alg_elem_t *x);

/** @brief Normalize representation of alg_elem x
 *
 * @param x Algebra element whose representation will be normalized
 *
 * Modification of x.
 * Sets coord and denom of x so that gcd(denom, content(coord))=1
 * without changing the value of x = (coord0/denom, coord1/denom, coord2/denom, coord3/denom).
 */
void quat_alg_normalize(quat_alg_elem_t *x);

/** @brief Test if x is 0
 *
 * @returns 1 if x=0, 0 otherwise
 *
 * x is 0 iff all coordinates in x->coord are 0
 */
int quat_alg_elem_is_zero(const quat_alg_elem_t *x);

/** @brief Test if x is 0
 *
 * @returns 1 if x=0, 0 otherwise
 *
 * x is 0 iff all coordinates in x are 0
 */
int quat_alg_coord_is_zero(const quat_alg_coord_t *x);

// end quat_quat_f
/** @}
 */

/** @defgroup quat_lat_f Lattice functions
 * @{
 */

void quat_lattice_add(quat_lattice_t *res, const quat_lattice_t *lat1, const quat_lattice_t *lat2);
void quat_lattice_intersect(quat_lattice_t *res,
                            const quat_lattice_t *lat1,
                            const quat_lattice_t *lat2);
void quat_lattice_mul(quat_lattice_t *res,
                      const quat_lattice_t *lat1,
                      const quat_lattice_t *lat2,
                      const quat_alg_t *alg);

/**
 * @brief Modifies a lattice to put it in hermite normal form
 *
 * In-place modification of the lattice.
 *
 * @param lat input lattice
 *
 * On a correct lattice this function changes nothing (since it is already in HNF), but it can be
 * used to put a handmade one in correct form in order to use the other lattice functions.
 */
void quat_lattice_hnf(quat_lattice_t *lat);

/**
 * @brief Test whether x ∈ lat. If so, compute its coordinates in lat's basis.
 *
 * @param coord Output: Set to the coordinates of x in lat. May be NULL.
 * @param lat The lattice
 * @param x An element of the quaternion algebra
 * @param alg The quaternion algebra
 * @return true if x ∈ lat
 */
int quat_lattice_contains(quat_alg_coord_t *coord,
                          const quat_lattice_t *lat,
                          const quat_alg_elem_t *x,
                          const quat_alg_t *alg);

/********************************* Functions from ideal.c ************************************/

/** @addtogroup quat_quat_f
 * @{
 */

/**
 * @brief Creates algebra element from scalar
 *
 * Resulting element has 1-coordinate equal to numerator/denominator
 *
 * @param elem Output: algebra element with numerator/denominator as first coordiante
 * (1-coordinate), 0 elsewhere (i,j,ij coordinates)
 * @param numerator
 * @param denominator Assumed  non zero
 */
void quat_alg_scalar(quat_alg_elem_t *elem, const ibz_t *numerator, const ibz_t *denominator);

/**
 * @brief Standard involution in a quaternion algebra
 *
 * @param conj Output: image of x by standard involution of the quaternion algebra alg
 * @param x element of alg whose image is searched
 */
void quat_alg_conj(quat_alg_elem_t *conj, const quat_alg_elem_t *x);

/**
 * @brief Given `x` ∈ `order`, factor it into its primitive and impritive parts
 *
 * Given `x` ∈ `order`, return a coordinate vector `primitive_x` and an integer `content`
 * such that `x` = `content` · Λ `primitive_x`, where Λ is the basis of `order`
 * and `x` / `content` is primitive in `order`.
 *
 * @param primitive_x Output: coordinates of a primitive element of `order` (in `order`'s basis)
 * @param content Output: content of `x`'s coordinate vector in order's basis
 * @param alg the quaternion algebra
 * @param order order of `alg`
 * @param x element of order, must be in `order`
 */
static inline void
quat_alg_make_primitive(quat_alg_coord_t *primitive_x,
                        ibz_t *content,
                        const quat_alg_elem_t *x,
                        const quat_order_t *order,
                        const quat_alg_t *alg)
{
    int ok = quat_lattice_contains(primitive_x, order, x, alg);
    assert(ok);
    ibz_content(content, primitive_x);
    ibz_t r;
    ibz_init(&r);
    for (int i = 0; i < 4; i++) {
        ibz_div(*primitive_x + i, &r, *primitive_x + i, content);
    }
    ibz_finalize(&r);
}

/**
 * @brief Tests if x ∈ order is primitive
 *
 * @param alg quaternion algebra
 * @param order quaternion order
 * @param x element of the order (fails if x ∉ order)
 *
 * @returns 1 if x is primitive, 0 otherwise
 */
static inline int
quat_alg_is_primitive(const quat_alg_elem_t *x, const quat_order_t *order, const quat_alg_t *alg)
{
    quat_alg_coord_t coord;
    ibz_t cnt;
    quat_alg_coord_init(&coord);
    ibz_init(&cnt);

    quat_alg_make_primitive(&coord, &cnt, x, order, alg);
    int ok = ibz_is_one(&cnt);

    ibz_finalize(&cnt);
    quat_alg_coord_finalize(&coord);
    return ok;
}

// end quat_quat_f
/** @}
 */

/** @defgroup quat_lideal_f Functions for left ideals
 * @{
 */

/** @defgroup quat_lideal_c Creating left ideals
 * @{
 */

/**
 * @brief Left principal ideal of order, generated by x
 *
 * @param lideal Output: left ideal
 * @param alg quaternion algebra
 * @param order maximal order of alg whose left ideal is searched
 * @param x generating element
 *
 * Creates the left ideal in 'order' generated by the element 'x'
 */
void quat_lideal_create_principal(quat_left_ideal_t *lideal,
                                  const quat_alg_elem_t *x,
                                  const quat_order_t *order,
                                  const quat_alg_t *alg);

/**
 * @brief Left ideal of order, generated by primitive x and N
 *
 * @param lideal Output: left ideal
 * @param alg quaternion algebra
 * @param order maximal order of alg whose left ideal is searched
 * @param x generating element, must be a primitive element of order
 * @param N generating integer
 *
 * Creates the left ideal in order generated by the element x and the integer N
 *
 */
void quat_lideal_create_from_primitive(quat_left_ideal_t *lideal,
                                       const quat_alg_elem_t *x,
                                       const ibz_t *N,
                                       const quat_order_t *order,
                                       const quat_alg_t *alg);

/**
 * @brief Make x primitive, remove content from N, then generate ideal
 *
 * @param lideal Output: left ideal
 * @param alg quaternion algebra
 * @param order maximal order of alg whose left ideal is searched
 * @param x generating element, a primitive element of order obtained from it will be used for
 * generation
 * @param N generating integer
 *
 * Given `x` = n·y ∈ order` with `y` primitive, given an integer `N`, create the ideal
 * generated by `y` and `N / gcd(n, N)`.
 *
 */
void quat_lideal_make_primitive_then_create(quat_left_ideal_t *lideal,
                                            const quat_alg_elem_t *x,
                                            const ibz_t *N,
                                            const quat_order_t *order,
                                            const quat_alg_t *alg);

/**
 * @brief Random left ideal of norm 2^e
 *
 * @param lideal Output: random left ideal (of parents alg and order) with norm 2^e
 * @param alg parent algebra for which an ideal is chosen. Is a quaterion algebra
 * @param order parent order for which an ideal is chosen. Must be maximal
 * @param e int64_t determining the norm of the resulting ideal
 * @param n Parameter controlling the amount of randomness used by the algorithm
 * @return 0 if PRNG failed, 1 otherwise.
 */
int quat_lideal_random_2e(quat_left_ideal_t *lideal,
                          const quat_order_t *order,
                          const quat_alg_t *alg,
                          int64_t e,
                          unsigned char n);

/** @}
 */

/** @defgroup quat_lideal_gen Generators of left ideals
 * @{
 */

/**
 * @brief Generator of 'lideal'
 *
 * @returns 1 if such a generator was found, 0 otherwise
 * @param gen Output: non scalar generator of lideal
 * @param lideal left ideal
 * @param alg the quaternion algebra
 * @param bound Bound used for enumeration of elements. Must be non-negative. If 0, a default value
 * is used.
 *
 * Ideal is generated by gen and the ideal's norm
 *
 * Bound has as default value QUATERNION_lideal_generator_search_bound
 */
int quat_lideal_generator(quat_alg_elem_t *gen,
                          const quat_left_ideal_t *lideal,
                          const quat_alg_t *alg,
                          int bound);

/**
 * @brief  Primitive generator of a left ideal of norm coprime to a given integer
 *
 * @returns 1 if such a generator was found, 0 otherwise
 * @param gen Output: generator of lideal, coprime to n
 * @param lideal left ideal
 * @param n value to which the generator norm should be coprime. (assumes gcd(n, norm(lideal)) = 1).
 * If this is not fulfilled, the returned element is a generator such that gcd(n^2,norm(gen)) =
 * gcd(n,norm(lideal))
 * @param alg the quaternion algebra
 * @param bound Bound used for enumeration of elements. Must be non-negative. If 0, a default value
 * 0 is used.
 *
 * Finds a primitive generator of 'lideal' of norm coprime with n (assumes gcd(n, norm(lideal)) = 1)
 *
 * gen is such that lideal is generated by gen and the ideal's norm
 *
 * Bound has as default value QUATERNION_lideal_generator_search_bound
 */
int quat_lideal_generator_coprime(quat_alg_elem_t *gen,
                                  const quat_left_ideal_t *lideal,
                                  const ibz_t *n,
                                  const quat_alg_t *alg,
                                  int bound);

/** @}
 */

/** @defgroup quat_lideal_op Operations on left ideals
 * @{
 */

/**
 * @brief  Left ideal product of left ideal I and element alpha
 *
 * @returns 1 if a product could be computed, 0 otherwise (in the later case, one might retry with a
 * higher bound)
 * @param product Output: lideal I*alpha, must have integer norm
 * @param lideal left ideal
 * @param alpha element multiplied to lideal to get the product ideal
 * @param alg the quaternion algebra
 * @param bound used for internal ideal_generator search. Must be positive. Setting it to 0 uses the
 * default value.
 *
 * I*alpha where I is a left-ideal and alpha an element of the algebra
 *
 * The resulting ideal must have an integer norm
 *
 * Bound has as default value QUATERNION_lideal_generator_search_bound
 */
int quat_lideal_mul(quat_left_ideal_t *product,
                    const quat_left_ideal_t *lideal,
                    const quat_alg_elem_t *alpha,
                    const quat_alg_t *alg,
                    int bound);

/**
 * @brief  Sum of two left ideals
 *
 * @param sum Output: Left ideal which is the sum of the 2 inputs
 * @param lideal1 left ideal
 * @param lideal2 left ideal
 * @param alg the quaternion algebra
 */
void quat_lideal_add(quat_left_ideal_t *sum,
                     const quat_left_ideal_t *lideal1,
                     const quat_left_ideal_t *lideal2,
                     const quat_alg_t *alg);

/**
 * @brief  Intersection of two left ideals
 *
 * @param intersection Output: Left ideal which is the intersection of the 2 inputs
 * @param lideal1 left ideal
 * @param lideal2 left ideal
 * @param alg the quaternion algebra
 */
void quat_lideal_inter(quat_left_ideal_t *intersection,
                       const quat_left_ideal_t *lideal1,
                       const quat_left_ideal_t *lideal2,
                       const quat_alg_t *alg);

/**
 * @brief  Equality test for left ideals
 *
 * @returns 1 if both left ideals are equal, 0 otherwise
 * @param lideal1 left ideal
 * @param lideal2 left ideal
 * @param alg the quaternion algebra
 */
int quat_lideal_equals(const quat_left_ideal_t *lideal1,
                       const quat_left_ideal_t *lideal2,
                       const quat_alg_t *alg);

/**
 * @brief  Element representing an isomorphism between I1 and I2
 *
 * @returns 1 if isomorphic, 0 otherwise
 * @param iso Output: algebra element such that I1*iso = I2.
 * @param lideal1 left ideal
 * @param lideal2 left ideal
 * @param alg the quaternion algebra
 *
 * If I1 and I2 are isomorphic, set `iso` to an element of `alg` such that I1*iso = I2,
 * and return 1. Otherwise return 0.
 *
 * I1 and I2 must have the same parent order (where "same" means they
 * point to the same object), in order to be considered isomorphic.
 */
int quat_lideal_isom(quat_alg_elem_t *iso,
                     const quat_left_ideal_t *lideal1,
                     const quat_left_ideal_t *lideal2,
                     const quat_alg_t *alg);

/**
 * @brief  Right order of a left ideal
 *
 * @param order Output: right order of the given ideal
 * @param lideal left ideal
 * @param alg the quaternion algebra
 */
void quat_lideal_right_order(quat_order_t *order,
                             const quat_left_ideal_t *lideal,
                             const quat_alg_t *alg);

/**
 * @brief LLL-reduce the basis of the left ideal, without considering its denominator
 *
 * This function reduce the basis of the lattice of the ideal, but it does completely ignore its
 * denominator. So the outputs of this function must still e divided by the appropriate power of
 * lideal.lattice.denom.
 *
 * @param reduced Output: Lattice defining the ideal, which has its basis in a lll-reduced form.
 * Must be divided by lideal.lattice.denom before usage
 * @param gram Output: gram matrix of the reduced basis. Must be divided by (lideal.lattice.denom)^2
 * before usage
 * @param lideal Ideal whose basis will be reduced
 * @param alg the quaternion algebra
 */
void quat_lideal_reduce_basis(ibz_mat_4x4_t *reduced,
                              ibz_mat_4x4_t *gram,
                              const quat_left_ideal_t *lideal,
                              const quat_alg_t *alg); // replaces lideal_lll

/** @}
 */

// end quat_lideal_f
/** @}
 */

/***************************** Functions from quaternion_tools.c
 * ***************************************/

/** @defgroup quat_order_op Operations on orders
 * @{
 */

/**
 * @brief  Connecting ideal of 2 orders in the same algebra
 *
 * @param connecting_ideal Output: ideal which is a right ideal of O1 and a left ideal of O2
 * @param alg quaternion algebra
 * @param order1 maximal order left of the searched ideal
 * @param order2 order right of the searched ideal
 */
void quat_connecting_ideal(quat_left_ideal_t *connecting_ideal,
                           const quat_order_t *order1,
                           const quat_order_t *order2,
                           const quat_alg_t *alg);

/**
 * @brief  LLL reduction on 4-dimensional lattice, coefficient is 0.99
 *
 * @param red Output: LLL reduced basis
 * @param lattice lattice with 4-dimensional basis
 * @param q parameter q for non-standard basis
 */
int quat_lattice_lll(ibz_mat_4x4_t *red,
                     const quat_lattice_t *lattice,
                     const ibz_t *q);

void from_1ijk_to_O0basis(ibz_vec_4_t *vec, const quat_alg_elem_t *el);

/** @}
 */

// end quat_quat
/** @}
 */

#endif
