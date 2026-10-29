/** @file
 *
 * @authors Sina Schaeffler
 *
 * @brief Declarations for helper functions for quaternion algebra implementation
 */

#ifndef QUAT_HELPER_H
#define QUAT_HELPER_H

#include <quaternion.h>

/** @internal
 * @ingroup quat_quat
 * @defgroup quat_helpers Quaternion module internal functions
 * @{
 */

/**  @internal
 * @defgroup quat_alg_helpers Helper functions for the alg library
 * @{
 */

/**  @internal
 * @brief helper function for initializing small quaternion algebras.
 */
static inline void
quat_alg_init_set_ui(quat_alg_t *alg, unsigned int p)
{
    ibz_t bp;
    ibz_init(&bp);
    ibz_set(&bp, p);
    quat_alg_init_set(alg, &bp);
    ibz_finalize(&bp);
}

/** @brief a+b
 *
 * Add two integer 4-vectors
 *
 * @param res Output: Will contain sum
 * @param a
 * @param b
 */
void quat_alg_coord_add(quat_alg_coord_t *res,
                        const quat_alg_coord_t *a,
                        const quat_alg_coord_t *b);

/** @brief a-b
 *
 * Substract two integer 4-vectors
 *
 * @param res Output: Will contain difference
 * @param a
 * @param b
 */
void quat_alg_coord_sub(quat_alg_coord_t *res,
                        const quat_alg_coord_t *a,
                        const quat_alg_coord_t *b);

/** @brief Compute same denominator form of two quaternion algebra elements
 *
 * res_a=a and res_b=b (representing the same element) and res_a.denom = res_b.denom
 *
 * @param res_a
 * @param res_b
 * @param a
 * @param b
 */
void quat_alg_equal_denom(quat_alg_elem_t *res_a,
                          quat_alg_elem_t *res_b,
                          const quat_alg_elem_t *a,
                          const quat_alg_elem_t *b);

/** @brief Copies the given values into an algebra element, without normalizing it
 *
 * @param elem Output: algebra element of coordinates [coord0,coord1,coord2,coord3] and denominator
 * denom
 * @param denom Denominator, must be non zero
 * @param coord0 Coordinate on 1 (0th vector of standard algebra basis)
 * @param coord1 Coordinate on i (1st vector of standard algebra basis)
 * @param coord2 Coordinate on j (2nd vector of standard algebra basis)
 * @param coord3 Coordinate on ij (3rd vector of standard algebra basis)
 */
void quat_alg_elem_copy_ibz(quat_alg_elem_t *elem,
                            const ibz_t *denom,
                            const ibz_t *coord0,
                            const ibz_t *coord1,
                            const ibz_t *coord2,
                            const ibz_t *coord3);

/** @brief Sets an algebra element to the given integer values, without normalizing it
 *
 * @param elem Output: algebra element of coordinates [coord0,coord1,coord2,coord3] and denominator
 * denom
 * @param denom Denominator, must be non zero
 * @param coord0 Coordinate on 1 (0th vector of standard algebra basis)
 * @param coord1 Coordinate on i (1st vector of standard algebra basis)
 * @param coord2 Coordinate on j (2nd vector of standard algebra basis)
 * @param coord3 Coordinate on ij (3rd vector of standard algebra basis)
 */
void quat_alg_elem_set(quat_alg_elem_t *elem,
                       int64_t denom,
                       int64_t coord0,
                       int64_t coord1,
                       int64_t coord2,
                       int64_t coord3);

/** @brief Multiplies algebra element by integer scalar, without normalizing it
 *
 * @param res Output
 * @param scalar Integer
 * @param elem Algebra element
 */
void quat_alg_elem_mul_by_scalar(quat_alg_elem_t *res,
                                 const ibz_t *scalar,
                                 const quat_alg_elem_t *elem);

/** @brief Compute the right multiplication table of a quaternion (without denominator)
 *
 * @param mulmat Output
 * @param a Quaternion
 * @param alg The algebra
 */
void quat_alg_rightmul_mat(ibz_mat_4x4_t *mulmat, const quat_alg_elem_t *a, const quat_alg_t *alg);
/** @}
 */

/**  @internal
 * @defgroup quat_int_helpers Helper functions for integer functions
 * @{
 */

/**  @internal
 * @defgroup quat_int_small_helpers Small integer functions
 * @{
 */

/** @brief round a/b to closest integer q
 */
void ibz_rounded_div(ibz_t *q, const ibz_t *a, const ibz_t *b);

/** @brief Compare ibz_t with long
 */
static int
ibz_cmp_si(ibz_t *x, int64_t y)
{
    ibz_t Y;
    ibz_init(&Y);
    ibz_set(&Y, y);
    int res = ibz_cmp(x, &Y);
    ibz_finalize(&Y);
    return res;
}
/** @}
 */

/**  @internal
 * @defgroup quat_cornacchia_helpers Helper functions for the cornacchia function
 * @{
 */

/** @brief Complex product of a and b
 *
 * re_res + i*im_res = (re_a+i*im_a)*(re_b+i*im_b) where i a usual complex 4th root of unity
 *
 * @param re_res Output: real part of the result
 * @param im_res Output: imaginary part of the result
 * @param re_a Real part of a
 * @param im_a Imaginary part of a
 * @param re_b Real part of b
 * @param im_b Imaginary part of b
 */
void ibz_complex_mul(ibz_t *re_res,
                     ibz_t *im_res,
                     const ibz_t *re_a,
                     const ibz_t *im_a,
                     const ibz_t *re_b,
                     const ibz_t *im_b);

/** @brief Multiplies res by a^e with res and a integer complex numbers
 *
 * re_res + i*im_res = (re_res+i*im_res)*((re_a+i*im_a)^exp) where i a usual complex 4th root of
 * unity
 *
 * @param re_res Output: real part of the result. Also used as input.
 * @param im_res Output: imaginary part of the result. Also used as input.
 * @param re_a Real part of a
 * @param im_a Imaginary part of a
 * @param exp res*(a^exp) will be computed, exp should be a positive integer or 0
 */
void ibz_complex_mul_by_complex_power(ibz_t *re_res,
                                      ibz_t *im_res,
                                      const ibz_t *re_a,
                                      const ibz_t *im_a,
                                      int64_t exp);

/** @brief Multiplies to res the result of the solutions of cornacchia for prime depending on
 * valuation val (prime-adic valuation)
 *
 * re_res + i*im_res = (re_res+i*im_res)*((x+i*y)^val) where i a usual complex 4th root of unity,
 * and x,y an integer sulotion to x^2 + y^2 = prime
 *
 * @param re_res Output: real part of the result. Also used as input.
 * @param im_res Output: imaginary part of the result. Also used as input.
 * @param prime a prime factor of n on which extended Cornacchia was called
 * @param val prime-adic valuation of the n on which extended Cornacchia was called
 * @returns 1 if an integer solution x,y to x^2 + y^2 = prime was found by Cornacchia_prime, 0
 * otherwise
 */
int ibz_cornacchia_extended_prime_loop(ibz_t *re_res, ibz_t *im_res, int64_t prime, int64_t val);
/** @}
 */
/** @}
 */

/**  @internal
 * @defgroup quat_dim4_helpers Helper functions for functions for matrices or vectors in dimension 4
 * @{
 */

/**  @internal
 * @defgroup quat_inv_helpers Helper functions for the integer matrix inversion function
 * @{
 */

/** @brief a1a2+b1b2+c1c2
 *
 * @param coeff Output: The coefficien which was computed as a1a2+b1b2-c1c2
 * @param a1
 * @param a2
 * @param b1
 * @param b2
 * @param c1
 * @param c2
 */
void ibz_inv_dim4_make_coeff_pmp(ibz_t *coeff,
                                 const ibz_t *a1,
                                 const ibz_t *a2,
                                 const ibz_t *b1,
                                 const ibz_t *b2,
                                 const ibz_t *c1,
                                 const ibz_t *c2);

/** @brief -a1a2+b1b2-c1c2
 *
 * @param coeff Output: The coefficien which was computed as -a1a2+b1b2-c1c2
 * @param a1
 * @param a2
 * @param b1
 * @param b2
 * @param c1
 * @param c2
 */
void ibz_inv_dim4_make_coeff_mpm(ibz_t *coeff,
                                 const ibz_t *a1,
                                 const ibz_t *a2,
                                 const ibz_t *b1,
                                 const ibz_t *b2,
                                 const ibz_t *c1,
                                 const ibz_t *c2);

/** @brief Matrix determinant and a matrix inv such that inv/det is the inverse matrix of the input
 *
 * Implemented following the methof of 2x2 minors explained at Method from
 * https://www.geometrictools.com/Documentation/LaplaceExpansionTheorem.pdf (visited on 3rd of May
 * 2023, 16h15 CEST)
 *
 * @returns 1 if the determinant of mat is not 0 and an inverse was computed, 0 otherwise
 * @param inv Output: Will contain an integer matrix which, dividet by det, will yield the rational
 * inverse of the matrix if it exists, can be NULL
 * @param det Output: Will contain the determinant of the input matrix, can be NULL
 * @param mat Matrix of which the inverse will be computed
 */
int ibz_mat_4x4_inv_with_det_as_denom(ibz_mat_4x4_t *inv, ibz_t *det, const ibz_mat_4x4_t *mat);

/** @brief a*b for a,b integer 4x4 matrices
 *
 * Naive implementation
 *
 * @param res Output: A 4x4 integer matrix
 * @param a
 * @param b
 */
void ibz_mat_4x4_mul(ibz_mat_4x4_t *res, const ibz_mat_4x4_t *a, const ibz_mat_4x4_t *b);
/** @}
 */

/**  @internal
 * @defgroup quat_lll_verify_helpers Helper functions for lll verification in dimension 4
 * @{
 */

/** @brief Set an ibq vector to 4 given integer coefficients
 */
void ibq_vec_4_copy_ibz(ibq_t (*vec)[4],
                        const ibz_t *coeff0,
                        const ibz_t *coeff1,
                        const ibz_t *coeff2,
                        const ibz_t *coeff3);

/** @brief Bilinear form vec00*vec10+vec01*vec11+q*vec02*vec12+q*vec03*vec13 for ibz_q
 */
void quat_dim4_lll_bilinear(ibq_t *b,
                            const ibq_t (*vec0)[4],
                            const ibq_t (*vec1)[4],
                            const ibz_t *q);

/** @brief Outputs the transposition of the orthogonalised matrix of mat (as fractions)
 *
 * For the bilinear form vec00*vec10+vec01*vec11+q*vec02*vec12+q*vec03*vec13
 */
void quat_dim4_gram_schmidt_transposed_with_ibq(ibq_t (*orthogonalised_transposed)[4][4],
                                                const ibz_mat_4x4_t *mat,
                                                const ibz_t *q);

/** @brief Verifies if mat is lll-reduced for parameter coeff and norm defined by q
 *
 * For the bilinear form vec00*vec10+vec01*vec11+q*vec02*vec12+q*vec03*vec13
 */
int quat_dim4_lll_verify(const ibz_mat_4x4_t *mat, const ibq_t *coeff, const ibz_t *q);
/** @}
 */

/**  @internal
 * @defgroup quat_dim4_lat_helpers Helper functions on vectors and matrices used mainly for lattices
 * @{
 */

/** @brief Set a vector of 4 integers to given values
 *
 * @param vec Output: is set to given coordinates
 * @param coord0
 * @param coord1
 * @param coord2
 * @param coord3
 */
void ibz_vec_4_set(ibz_vec_4_t *vec,
                   int64_t coord0,
                   int64_t coord1,
                   int64_t coord2,
                   int64_t coord3);

/** @brief Copy all values from one vector to another
 *
 * @param new Output: is set to same values as vec
 * @param vec
 */
void ibz_vec_4_copy(ibz_vec_4_t *new, const ibz_vec_4_t *vec);

/** @brief Compute the linear combination lc = coeff_a vec_a + coeff_b vec_b
 *
 * @param lc Output: linear combination lc = coeff_a vec_a + coeff_b vec_b
 * @param coeff_a Scalar multiplied to vec_a
 * @param vec_a
 * @param coeff_b Scalar multiplied to vec_b
 * @param vec_b
 */
void ibz_vec_4_linear_combination(ibz_vec_4_t *lc,
                                  const ibz_t *coeff_a,
                                  const ibz_vec_4_t *vec_a,
                                  const ibz_t *coeff_b,
                                  const ibz_vec_4_t *vec_b);

/** @brief divides all values in vector by same scalar
 *
 * @returns 1 if scalar divided all values in mat, 0 otherwise (division is performed in both cases)
 * @param quot Output
 * @param scalar
 * @param vec
 */
int ibz_vec_4_scalar_div(ibz_vec_4_t *quot, const ibz_t *scalar, const ibz_vec_4_t *vec);

/** @brief Negation for vectors of 4 integers
 *
 * @param neg Output: is set to -vec
 * @param vec
 */
void ibz_vec_4_negate(ibz_vec_4_t *neg, const ibz_vec_4_t *vec);

/** @brief Copies all values from a 4x4 integer matrix to another one
 *
 * @param new Output: matrix which will have its entries set to mat's entries
 * @param mat Input matrix
 */
void ibz_mat_4x4_copy(ibz_mat_4x4_t *new, const ibz_mat_4x4_t *mat);

/** @brief -mat for mat a 4x4 integer matrix
 *
 * @param neg Output: is set to -mat
 * @param mat Input matrix
 */
void ibz_mat_4x4_negate(ibz_mat_4x4_t *neg, const ibz_mat_4x4_t *mat);

/** @brief transpose a 4x4 integer matrix
 *
 * @param transposed Output: is set to the transposition of mat
 * @param mat Input matrix
 */
void ibz_mat_4x4_transpose(ibz_mat_4x4_t *transposed, const ibz_mat_4x4_t *mat);

/** @brief Set all coefficients of a matrix to zero for 4x4 integer matrices
 *
 * @param zero
 */
void ibz_mat_4x4_zero(ibz_mat_4x4_t *zero);

/** @brief Set a matrix to the identity for 4x4 integer matrices
 *
 * @param id
 */
void ibz_mat_4x4_identity(ibz_mat_4x4_t *id);

/** @brief Test equality to identity for 4x4 integer matrices
 *
 * @returns 1 if mat is the identity matrix, 0 otherwise
 * @param mat
 */
int ibz_mat_4x4_is_identity(const ibz_mat_4x4_t *mat);

/** @brief Equality test for 4x4 integer matrices
 *
 * @returns 1 if equal, 0 otherwise
 * @param mat1
 * @param mat2
 */
int ibz_mat_4x4_equal(const ibz_mat_4x4_t *mat1, const ibz_mat_4x4_t *mat2);

/** @brief Matrix by integer multiplication
 *
 * @param prod Output
 * @param scalar
 * @param mat
 */
void ibz_mat_4x4_scalar_mul(ibz_mat_4x4_t *prod, const ibz_t *scalar, const ibz_mat_4x4_t *mat);

/** @brief gcd of all values in matrix
 *
 * @param gcd Output
 * @param mat
 */
void ibz_mat_4x4_gcd(ibz_t *gcd, const ibz_mat_4x4_t *mat);

/** @brief divides all values in matrix by same scalar
 *
 * @returns 1 if scalar divided all values in mat, 0 otherwise (division is performed in both cases)
 * @param quot Output
 * @param scalar
 * @param mat
 */
int ibz_mat_4x4_scalar_div(ibz_mat_4x4_t *quot, const ibz_t *scalar, const ibz_mat_4x4_t *mat);

/** @brief Modular matrix multiplication of aribitrarily sized matrices
 *
 *    res = A * B (mod)
 *
 * @param from
 * @param through
 * @param to
 * @param res Output: a from × to matrix. Cannot point to the same memory as A or B.
 * @param A a from × through matrix
 * @param B a through × to matrix
 * @param mod modulo
 */
void ibz_mat_mulmod(int from,
                    int through,
                    int to,
                    ibz_t res[from][to],
                    const ibz_t A[from][through],
                    const ibz_t B[through][to],
                    const ibz_t *mod);

/** @brief Compute the Howell form of a matrix modulo an integer
 *
 * Source: https://link.springer.com/chapter/10.1007/3-540-68530-8_12
 * Adapted from PARI/GP
 *
 * @param rows The number of rows of the input
 * @param cols The number of columns of the input, must be <= rows
 * @param howell Output: the Howell form H of mat
 * @param trans Output: the transformation matrix U s.t. mat·U = H. May be NULL.
 * @param mat The matrix
 * @param mod The integer modulus
 * @return the number of zero-columns to the lef of `howell`.
 */
int ibz_mat_howell(int rows,
                   int cols,
                   ibz_t howell[rows][rows + 1],
                   ibz_t trans[rows + 1][rows + 1],
                   const ibz_t mat[rows][cols],
                   ibz_t *mod);

/** @brief Compute the right kernel of a matrix modulo an integer
 *
 * Computes the Howell normal form of the kernel.
 *
 * Source: https://link.springer.com/chapter/10.1007/3-540-68530-8_12
 * Adapted from PARI/GP
 *
 * @param rows The number of rows of the input
 * @param cols The number of columns of the input, must be <= rows
 * @param ker Output: the kernel
 * @param mat The matrix
 * @param mod The integer modulus
 */
void ibz_mat_right_ker_mod(int rows,
                           int cols,
                           ibz_t ker[cols][cols],
                           const ibz_t mat[rows][cols],
                           ibz_t *mod);

/** @brief Verifies whether the 4x4 input matrix is in Hermite Normal Form
 *
 * @returns 1 if mat is in HNF, 0 otherwise
 * @param mat Matrix to be tested
 */
int ibz_mat_4x4_is_hnf(const ibz_mat_4x4_t *mat);

/** @brief Hermite Normal Form of a matrix of 8 integer vectors
 *
 * Algorithm used is the one at number 2.4.5 in Henri Cohen's "A Course in Computational Algebraic
 * Number Theory" (Springer Verlag, in series "Graduate texts in Mathematics") from 1993
 *
 * @param hnf Output: Matrix in Hermite Normal Form generating the same lattice as generators
 * @param generators matrix whose colums generate the same lattice than the output
 */
void ibz_mat_4x8_hnf_core(ibz_mat_4x4_t *hnf, const ibz_mat_4x8_t *generators);

/** @brief Hermite Normal Form of a matrix concatenated with mod*Id
 *
 * @param hnf Output: Matrix in Hermite Normal Form generating the same lattice as generators
 * @param mat matrix whose colums and mod*Id generate the same lattice than the output
 * @param mod mod*Id is appended to the matrix. A hnf of this concatenation is then output
 */
void ibz_mat_4x4_hnf_mod(ibz_mat_4x4_t *hnf, const ibz_mat_4x4_t *mat, const ibz_t *mod);

/** @}
 */
/** @}
 */

/**  @internal
 * @defgroup quat_dim2_helpers Helper functions for dimension 2
 * @{
 */

/**  @internal
 * @defgroup quat_dim2_other_helpers Set and other small helper functions for dimension 2 matrix and
 * vector
 * @{
 */

/** @brief Set vector coefficients to the given integers
 *
 * @param vec Output: Vector
 * @param a0
 * @param a1
 */
void ibz_vec_2_set(ibz_vec_2_t *vec, int a0, int a1);

/** @brief Determinant of a 2x2 integer matrix given as 4 integers
 *
 * @param det Output: Determinant of the matrix
 * @param a11 matrix coefficient (upper left corner)
 * @param a12 matrix coefficient (upper right corner)
 * @param a21 matrix coefficient (lower left corner)
 * @param a22 matrix coefficient (lower right corner)
 */
void ibz_mat_2x2_det_from_ibz(ibz_t *det,
                              const ibz_t *a11,
                              const ibz_t *a12,
                              const ibz_t *a21,
                              const ibz_t *a22);
/** @}
 */

/**  @internal
 * @defgroup quat_cvp_helpers Helper functions for 2x2 cvp
 * @{
 */

/** @brief Checks if the vector (coord1,coord2) has integer coordinates in basis
 *
 * @param basis Rank 2 matrix
 * @param coord1
 * @param coord2
 * @returns 1 if the vector (coord1,coord2) has integer coordinates in basis, 0 otherwise
 */
int quat_dim2_lattice_contains(ibz_mat_2x2_t *basis, ibz_t *coord1, ibz_t *coord2);

/** @brief coord1^2 + norm_q*coord2^2
 *
 * This defines a quadratic form in dimension 2 where coord1 is the first and coord2 the second
 * coordinate of the vector on which it is evaluated
 *
 * @param norm Output: coord1^2 + norm_q*coord2^2
 * @param coord1
 * @param coord2
 * @param norm_q Positive integer
 */
void quat_dim2_lattice_norm(ibz_t *norm,
                            const ibz_t *coord1,
                            const ibz_t *coord2,
                            const ibz_t *norm_q);

/** @brief v11*v21 + norm_q*v12*v22
 *
 * This defines a bilinear form in dimension 2 where v11,v12 are coordinates of the first vector,
 * v21,v22 of the second vector
 *
 * @param res Output: v11*v21+q*v12*v22
 * @param v11
 * @param v12
 * @param v21
 * @param v22
 * @param norm_q Positive integer
 */
void quat_dim2_lattice_bilinear(ibz_t *res,
                                const ibz_t *v11,
                                const ibz_t *v12,
                                const ibz_t *v21,
                                const ibz_t *v22,
                                const ibz_t *norm_q);

/** @brief Basis of the integral lattice represented by basis, which is small for the norm x^2 +
 * qy^2 (in standard basis)
 *
 * Additionally, the first vector in the basis has a smaller norm than the second one.
 *
 * Algorithm 1.3.14 from Henri Cohen's "A Course in Computational Algebraic Number Theory" (Springer
 * Verlag, in series "Graduate texts in Mathematics") from 1993 which finds a shortest vector in the
 * lattice.
 *
 * @param reduced Output: Matrix of 2 column vectors of small norm x^2 + qy^2 which are a basis of
 * the lattice the basis argument represents
 * @param basis Basis of a rank 2 lattice in dimension 2
 * @param norm_q Positive integer defining a quadratic form x^2 + qy^2 (x,y coordinates of a vector
 * in the standard basis of R^2) for which the reduced output basis shound be small
 */
void quat_dim2_lattice_short_basis(ibz_mat_2x2_t *reduced,
                                   const ibz_mat_2x2_t *basis,
                                   const ibz_t *norm_q);

/** @brief Uses a and b to compute a* orthogonal to b, then computes the projection res of t on a*
 * (uses the norm associated to norm_q)
 *
 * Helper for quat_dim2_lattice_closest_vector, implicitly computes an orthogonalised basis (b,a*)
 * from (b,a) and a projection f the target t on its second vector
 *
 * Uses the norm associated to norm_q by x^2 + qy^2, for x,y coordinates of a vector
 *
 * @param res Output: The coefficient (projection of t on a* orthogonal to b) which was computed
 * @param a0 will be the 1st coeff of a, the second vector of the input basis
 * @param a1 will be the 2nd coeff of a, the second vector of the input basis
 * @param b0 will be the 1st coeff of b, the first vector of the input basis
 * @param b1 will be the 2nd coeff of b, the first vector of the input basis
 * @param t0 will be the 1st coeff of the target vector, which one wnat to project on the
 * orthogonalised basis' second vector
 * @param t1 will be the 2nd coeff of the target vector, which one wnat to project on the
 * orthogonalised basis' second vector
 * @param norm_q Positive integer defining a quadratic form x^2 + qy^2
 */
void quat_dim2_lattice_get_coefficient_with_orthogonalisation(ibz_t *res,
                                                              const ibz_t *a0,
                                                              const ibz_t *a1,
                                                              const ibz_t *b0,
                                                              const ibz_t *b1,
                                                              const ibz_t *t0,
                                                              const ibz_t *t1,
                                                              const ibz_t *norm_q);

/** @brief Finds a vector close to the given target in a lattice of which a reduced basis is given
 *
 * Nearest plane algo as in https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/cvp.pdf
 * (15.5.23,16h10), but without basis reduction: Basically just two projections
 *
 * @param target_minus_closest Output: Vector in standard basis corresponding to target minus the
 * close vector in the lattice which is output in closest_coords_in_basis
 * @param closest_coords_in_basis Output: Represents a vector in the lattice close to target,
 * represented by its coordinates in the given absis of the lattice
 * @param reduced_basis Reduced basis of the lattice, reduction should be done using lll or an exact
 * shortest vector algorithm
 * @param target vector to which the solution should be close
 * @param norm_q Positive integer defining a quadratic form x^2 + qy^2 (x,y coordinates of a vector
 * in the standard basis of R^2) for which the reduced output basis shound be small
 */
void quat_dim2_lattice_closest_vector(ibz_vec_2_t *target_minus_closest,
                                      ibz_vec_2_t *closest_coords_in_basis,
                                      const ibz_mat_2x2_t *reduced_basis,
                                      const ibz_vec_2_t *target,
                                      const ibz_t *norm_q);

/** @brief give a,b,c such that ax^2 + bxy + cy^2 = N(Bz), where B is the basis, z the vector x,y
 * and N the quadratic form (coord1^2 + q coord2^2)
 *
 * @param qf_a Output: b in the formula
 * @param qf_b Output: b in the formula
 * @param qf_c Output: c in the formula
 * @param basis Basis of the lattice
 * @param norm_q Positive integer defining a quadratic form x^2 + qy^2 (x,y coordinates of a vector
 * in the standard basis of R^2) for which the reduced output basis shound be small
 */
void quat_dim2_lattice_get_qf_on_lattice(ibz_t *qf_a,
                                         ibz_t *qf_b,
                                         ibz_t *qf_c,
                                         const ibz_mat_2x2_t *basis,
                                         const ibz_t *norm_q);

/** @brief Test version of the condition argument in the cvp enumeration algorithms.
 *
 * Sets elem[0] and elem[2] to vec[0], elem[1] and elem[3] to vec[1] if vec[0] + vec[1] mod p is 2,
 * where p is the ibz_t to which params points
 *
 * This defines a quadratic form in dimension 2 where coord1 is the first and coord2 the second
 * coordinate of the vector on which it is evaluated
 *
 * @param elem Output as described below
 * @param vec
 * @param params void* which must point to an ibz_t
 */
int quat_dim2_lattice_test_cvp_condition(quat_alg_elem_t *elem,
                                         const ibz_vec_2_t *vec,
                                         const void *params);

/**
 * @brief Find vector of small norm in a positive definite quadratic form, satisfying extra
 * conditions.
 *
 * @param res Output: The quat_alg_elem (dimension 4, with denominator) which the condition sets
 * when it is fulfilled
 * @param x first coordinate in the lattice basis lat_basis of a short vector (for the norm written
 * coeff1^2 + q coeff2 ^2 in the standard basis)
 * @param y first coordinate in the lattice basis lat_basis of a short vector (for the norm written
 * coeff1^2 + q coeff2 ^2 in the standard basis)
 * @param condition a filter function returning whether res is set to a valid output or not. The
 * algorithm stops when it succeeds (outputs 1)
 * @param params extra parameters passed to `condition`. May be NULL.
 * @param target_minus_closest vector which will be added to the enumerated short vectors before
 * checking the bound
 * @param lat_basis reduced basis of the lattice, in which a short vector is searched for
 * @param norm_q defines the quadratic form coord1^2+norm_q*coord2^2 (in standard basis) used as
 * norm
 * @param norm_bound only vectors with norm smaller than this bound are tested for condition
 * @return 1 if vector was found, 0 otherwise
 */
int quat_dim2_lattice_bound_and_condition(quat_alg_elem_t *res,
                                          const ibz_t *x,
                                          const ibz_t *y,
                                          int (*condition)(quat_alg_elem_t *,
                                                           const ibz_vec_2_t *,
                                                           const void *),
                                          const void *params,
                                          const ibz_vec_2_t *target_minus_closest,
                                          const ibz_mat_2x2_t *lat_basis,
                                          const ibz_t *norm_q,
                                          const ibz_t *norm_bound);

/** @brief Computes an integer slightly larger than sqrt(num_a/denom_a)+num_b/denom_b.
 *
 * More precisely, if denoting sqrt_ the integer part of the square root, and _ the integer part of
 * a rational, res = 1+_((sqrt_(num_a)+1)/sqrt_(denom_a) + num_b/denom_b)
 *
 * @param res upper approximation of sqrt(num_a/denom_a)+num_b/denom_b
 * @param num_a must be of same sign as denom_a
 * @param denom_a must be non 0 and of same sign as num_a
 * @param num_b
 * @param denom_b must be non 0
 */
int quat_dim2_lattice_qf_value_bound_generation(ibz_t *res,
                                                const ibz_t *num_a,
                                                const ibz_t *denom_a,
                                                const ibz_t *num_b,
                                                const ibz_t *denom_b);

/**
 * @brief Find vector of small norm in a positive definite quadratic form, satisfying extra
 * conditions.
 *
 * Enumerates up to `max_tries` vectors `(x,y)` such that `qfa x² + qfb xy + qfc y² < norm_bound`;
 * the first vector such that
 * `quat_dim2_lattice_bound_and_condition(res,x,y,condition,params,target_minus_closest,lat_basis,
 * norm_q,norm_bound) == 1` is returned. The vector enumeration starts by vectors close to the bound
 *
 * Uses algorithm 2.7.5 (Fincke-Pohst) from Henri Cohen's "A Course in Computational Algebraic
 * Number Theory" (Springer Verlag, in series "Graduate texts in Mathematics") from 1993 Slightly
 * adapted to work without rational numbers and their square roots Therefore needing a test to make
 * sure the bounds are respected, which is integrated in quat_dim2_lattice_bound_and_condition Also
 * the norm bound is initialised a bit lower that the bound received, to leave space for the added
 * target_minus_closest
 *
 * @param res Output: selected vector (x,y)
 * @param condition a filter function returning whether a vector should be output or not
 * @param params extra parameters passed to `condition`. May be NULL.
 * @param target_minus_closest vector which will be added to the enumerated short vectors before
 * checking the bound
 * @param lat_basis reduced basis of the lattice, in which a short vector is searched for
 * @param norm_q defines the quadratic form coord1^2+norm_q*coord2^2 (in standard basis) used as
 * norm
 * @param norm_bound only vectors with norm smaller than this bound are tested for condition and
 * output
 * @param max_tries maximum number of calls to filter
 * @return 1 if vector was found, 0 otherwise
 */
int quat_dim2_lattice_qf_enumerate_short_vec(quat_alg_elem_t *res,
                                             int (*condition)(quat_alg_elem_t *,
                                                              const ibz_vec_2_t *,
                                                              const void *),
                                             const void *params,
                                             const ibz_vec_2_t *target_minus_closest,
                                             const ibz_mat_2x2_t *lat_basis,
                                             const ibz_t *norm_q,
                                             const ibz_t *norm_bound,
                                             const int max_tries);
/** @}
 */
/** @}
 */

/**  @internal
 * @defgroup quat_lattice_helper Helper functions for the lattice library (dimension 4)
 * @{
 */

/**
 * @brief Lattice equality
 *
 * Lattice bases are assumed to be under HNF, but denominators are free.
 *
 * @returns 1 if both lattices are equal, 0 otherwise
 */
int quat_lattice_equal(const quat_lattice_t *lat1, const quat_lattice_t *lat2);

/** @brief Divides basis and denominator of a lattice by their gcd
 *
 * @param reduced Output
 * @param lat Lattice
 */
void quat_lattice_reduce_denom(quat_lattice_t *reduced, const quat_lattice_t *lat);

/**
 * @brief Computes the dual lattice of lat, without putting its basis in HNF
 *
 * This function returns a lattice not under HNF. For careful internal use only.
 *
 * Coputation method described in https://cseweb.ucsd.edu/classes/sp14/cse206A-a/lec4.pdf consulted
 * on 19 of May 2023, 12h40 CEST
 *
 * @param dual Output: The dual lattice of lat. ATTENTION: is not under HNF. hnf computation must be
 * applied before using lattice functions on it
 * @param lat lattice, the dual of it will be computed
 */
void quat_lattice_dual_without_hnf(quat_lattice_t *dual, const quat_lattice_t *lat);

/**
 * @brief Test whether x ∈ lat. If so, compute its coordinates in lat's basis.
 *
 * Lattice assumed of full rank and under HNF, none of both is tested so far.
 *
 * @param coord Output: Set to the coordinates of x in lat
 * @param lat The lattice
 * @param x An element of the quaternion algebra, in same basis as the lattice lat
 * @return true if x ∈ lat
 */
int quat_lattice_contains_without_alg(quat_alg_coord_t *coord,
                                      const quat_lattice_t *lat,
                                      const quat_alg_elem_t *x);

/** @brief The index of sublat into overlat
 *
 * Assumes inputs are in HNF.
 *
 * @param index Output
 * @param sublat A lattice in HNF, must be sublattice of overlat
 * @param overlat A lattice in HNF, must be overlattice of sublat
 */
void quat_lattice_index(ibz_t *index, const quat_lattice_t *sublat, const quat_lattice_t *overlat);

/** @brief Random lattice element from a small parallelogram
 *
 * Sample a random element in `lattice` by taking a random linear
 * combination of the basis with uniform coefficients in
 * [-2^(n-1),2^(n-1)-1].
 *
 * @param elem Output element
 * @param lattice Whence the element is sampled
 * @param n Number of random bits for the coefficients. Must be <= 64.
 * @return 0 if PRNG failed (in this case elem is set to 0), 1 otherwise
 */
int quat_lattice_random_elem(quat_alg_elem_t *elem, const quat_lattice_t *lattice, unsigned char n);

/** @brief Compute the right transporter from lat1 to lat2
 *
 * The ideal of those x such that lat1·x ⊂ lat2
 */
void quat_lattice_right_transporter(quat_lattice_t *trans,
                                    const quat_lattice_t *lat1,
                                    const quat_lattice_t *lat2,
                                    const quat_alg_t *alg);

/** @}
 */
/** @}
 */
/** @}
 */

#endif
