/** @file
 *
 * @authors Antonin Leroux
 *
 * @brief The HD-isogenies algorithm required by the signature
 *
 */

#ifndef HD_H
#define HD_H

#include <ec.h>
#include <torsion_constants.h>
#include <stdio.h>
#include <curve_extras.h>

/** @brief Type for couple point *
 * @typedef theta_couple_point_t
 *
 * @struct theta_couple_point
 *
 * the  theta_couple_point structure
 */
typedef struct theta_couple_point
{
    ec_point_t P1;
    ec_point_t P2;
} theta_couple_point_t;

typedef struct theta_couple_jac_point
{
    jac_point_t P1;
    jac_point_t P2;
} theta_couple_jac_point_t;

/** @brief Type for couple curve *
 * @typedef theta_couple_curve_t
 *
 * @struct theta_couple_curve
 *
 * the  theta_couple_curve structure
 */
typedef struct theta_couple_curve
{
    ec_curve_t E1;
    ec_curve_t E2;
} theta_couple_curve_t;

/** @brief Type for theta point *
 * @typedef theta_point_t
 *
 * @struct theta_point
 *
 * the  theta_point structure used
 */
typedef struct theta_point
{
    fp2_t x;
    fp2_t y;
    fp2_t z;
    fp2_t t;
} theta_point_t;

/** @brief Type for theta structure *
 * @typedef theta_structure_t
 *
 * @struct theta_structure
 *
 * the  theta_structure structure used
 */
typedef struct theta_structure
{
    theta_point_t null_point;
    int precomputation;
    // fp2_t y0;
    // fp2_t z0;
    // fp2_t t0;

    fp2_t XYZ0;
    fp2_t YZT0;
    fp2_t XZT0;
    fp2_t XYT0;
    fp2_t xyz0;
    fp2_t yzt0;
    fp2_t xzt0;
    fp2_t xyt0;
} theta_structure_t;

/** @brief Type for gluing (2,2) theta isogeny *
 * @typedef theta_gluing_t
 *
 * @struct theta_gluing
 *
 * the  theta_gluing structure
 */
typedef struct theta_gluing
{

    theta_couple_curve_t domain;
    theta_couple_point_t K1_4;
    theta_couple_point_t K2_4;
    theta_couple_jac_point_t xyK1_4;
    theta_couple_jac_point_t xyK2_4;
    theta_point_t T1_8;
    theta_point_t T2_8;

    fp2_t M00;
    fp2_t M01;
    fp2_t M02;
    fp2_t M03;

    fp2_t M10;
    fp2_t M11;
    fp2_t M12;
    fp2_t M13;

    fp2_t M20;
    fp2_t M21;
    fp2_t M22;
    fp2_t M23;

    fp2_t M30;
    fp2_t M31;
    fp2_t M32;
    fp2_t M33;
    int32_t zero_idx;
    theta_point_t precomputation;
    theta_point_t codomain;
} theta_gluing_t;

/** @brief Type for standard (2,2) theta isogeny *
 * @typedef theta_isogeny_t
 *
 * @struct theta_isogeny
 *
 * the  theta_isogeny structure
 */
typedef struct theta_isogeny
{
    theta_point_t T1_8;
    theta_point_t T2_8;
    int bool1;
    int bool2;
    theta_structure_t domain;
    theta_point_t precomputation;
    theta_structure_t codomain;
} theta_isogeny_t;

/** @brief Type for splitting isomorphism *
 * @typedef theta_splitting_t
 *
 * @struct theta_splitting
 *
 * the theta_splitting structure
 */
typedef struct theta_splitting
{

    fp2_t M00;
    fp2_t M01;
    fp2_t M02;
    fp2_t M03;

    fp2_t M10;
    fp2_t M11;
    fp2_t M12;
    fp2_t M13;

    fp2_t M20;
    fp2_t M21;
    fp2_t M22;
    fp2_t M23;

    fp2_t M30;
    fp2_t M31;
    fp2_t M32;
    fp2_t M33;
    theta_structure_t B;

} theta_splitting_t;

/** @brief Type for chain of (2,2) theta isogenies with preimage by 4 multiplication above *
 * @typedef theta_chain_t
 *
 * @struct theta_chain
 *
 * the  theta_chain structure
 */
typedef struct theta_chain
{
    theta_couple_point_t T1;
    theta_couple_point_t T2;
    int length;
    theta_couple_curve_t domain;
    theta_couple_curve_t codomain;
    theta_gluing_t first_step;
    theta_splitting_t last_step;
    theta_isogeny_t *steps;
} theta_chain_t;

/*************************** Functions *****************************/

/**
 * @brief Compute the iterated double of the theta couple point in on the elliptic product E12
 *
 * @param out Output: the theta_couple_point
 * @param n : the number of iteration
 * @param E12 an elliptic product
 * @param in the theta couple point in the elliptic product
 * in = (P1,P2)
 * out = [2^n] (P1,P2)
 *
 */
void double_couple_point_iter(theta_couple_point_t *out,
                              int n,
                              const theta_couple_curve_t *A,
                              const theta_couple_point_t *in);

/**
 * @brief Compute the iterated double of the theta couple jac point in on the elliptic product E12
 *
 * @param out Output: the theta_couple_jac_point
 * @param n : the number of iteration
 * @param E12 an elliptic product
 * @param in the theta couple jac point in the elliptic product
 * in = (P1,P2)
 * out = [2^n] (P1,P2)
 *
 */
void double_couple_jac_point_iter(theta_couple_jac_point_t *out,
                                  int n,
                                  const theta_couple_curve_t *A,
                                  const theta_couple_jac_point_t *in);

void couple_jac_to_xz(theta_couple_point_t *P, const theta_couple_jac_point_t *xyP);

/**
 * @brief Compute the double of the theta couple point in on the elliptic product E12
 *
 * @param out Output: the theta_couple_point
 * @param E12 an elliptic product
 * @param in the theta couple point in the elliptic product
 * in = (P1,P2)
 * out = [2] (P1,P2)
 *
 */
void double_couple_point(theta_couple_point_t *out,
                         const theta_couple_curve_t *A,
                         const theta_couple_point_t *in);

/**
 * @brief Compute the addition of theta couple points in the elliptic product E12
 *
 * @param out Output: the theta_couple_point
 * @param E12 an elliptic product
 * @param T1 a theta couple point in the elliptic product
 * @param T2 a theta couple point in the elliptic product
 * T1 = (P1,P2) T2 = (Q1,Q2)
 * out = (P1+Q1,P2+Q2)
 *
 */
void add_couple_point(theta_couple_point_t *out,
                      const theta_couple_curve_t *A,
                      const theta_couple_point_t *T1,
                      const theta_couple_point_t *T2);

/**
 * @brief Compute  a (2,2) isogeny chain in dimension 2 between elliptic products in the theta_model
 *
 * @param out Output: the theta_chain
 * @param n : the length of the isogeny chain
 * @param E12 an elliptic curve product
 * @param T1 a couple point on E12[2^(n+2)]
 * @param T2 a couple point on E12[2^(n+2)]
 * @param T1m2 a couple point on E12[2^(n+2)] equal to T1-T2
 * @param strategy a strategy
 * @param eight_above, 0 or 1, indicating if we give the points in E12[2^n] or E12[2^(n+2)]
 *
 * out : E1xE2 -> E3xE4 of kernel [4](T1,T2)
 * uses the strategy given in input
 *
 */
void theta_chain_comput_strategy(theta_chain_t *out,
                                 int n,
                                 theta_couple_curve_t *E12,
                                 const theta_couple_point_t *T1,
                                 const theta_couple_point_t *T2,
                                 const theta_couple_point_t *T1m2,
                                 int *strategy,
                                 int eight_above);

void theta_chain_comput_strategy_faster_no_eval(theta_chain_t *out,
                                                int n,
                                                theta_couple_curve_t *E12,
                                                const theta_couple_point_t *T1,
                                                const theta_couple_point_t *T2,
                                                const theta_couple_point_t *T1m2,
                                                int *strategy,
                                                int eight_above);

/**
 * @brief Evaluate a (2,2) isogeny chain in dimension 2 between elliptic products in the theta_model
 *
 * @param out Output: the image point
 * @param phi : the (2,2) isogeny chain of domain E12
 * @param P12 a couple point on E12,
 * @param Help a couple point on E12
 *
 * phi : E1xE2 -> E3xE4 of kernel
 * P12 in E1xE2
 * out = phi(P12) in E3xE4
 * Help is equal to phi.first_step.K1_4 + P12
 *
 */
void theta_chain_eval(theta_couple_point_t *out,
                      theta_chain_t *phi,
                      theta_couple_point_t *P12,
                      const theta_couple_point_t *Help);

/**
 * @brief Evaluate a (2,2) isogeny chain in dimension 2 between elliptic products in the theta_model
 *
 * @param out Output: the image point
 * @param phi : the (2,2) isogeny chain of domain E12
 * @param P12 a couple jac point on E12,
 *
 * phi : E1xE2 -> E3xE4 of kernel
 * P12 in E1xE2
 * out = phi(P12) in E3xE4
 *
 */
void theta_chain_eval_no_help(theta_couple_point_t *out,
                              theta_chain_t *phi,
                              theta_couple_jac_point_t *P12,
                              const theta_couple_curve_t *E12);

/**
 * @brief Evaluate a (2,2) isogeny chain in dimension 2 between elliptic products in the theta_model
 *
 * @param out Output: the image point
 * @param phi : the (2,2) isogeny chain of domain E12
 * @param P12 a couple point on E12 where one of the two point is zero,
 *
 * phi : E1xE2 -> E3xE4 of kernel
 * P12 in E1xE2 with P12 = (P1,0) or (0,P2)
 * out = phi(P12) in E3xE4
 *
 */
void theta_chain_eval_special_case(theta_couple_point_t *out,
                                   theta_chain_t *phi,
                                   theta_couple_point_t *P12,
                                   const theta_couple_curve_t *E12);

void theta_print(char *name, theta_point_t P);

#endif