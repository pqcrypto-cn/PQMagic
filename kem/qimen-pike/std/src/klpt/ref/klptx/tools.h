#include <intbig.h>
#include <quaternion.h>
#include <klpt.h>

/** @file
 *
 * @authors Antonin Leroux
 *
 * @brief the klpt_tools header
 */

#ifndef KLPT_TOOLS_H
#define KLPT_TOOLS_H

/** @internal
 * @ingroup klpt_klpt
 * @defgroup klpt_internal KLPT module internal functions and types
 * @{
 */

/** @internal
 * @defgroup klpt_param_t Types for klpt parameters
 * @{
 */

/** @brief Type for klpt parameter *
 * @typedef signing_klpt_param_t
 *
 * @struct signing_klpt_param
 *
 * the structure used in klpt for the call to strong approx
 */
typedef struct signing_klpt_param
{

    quat_alg_elem_t gamma;
    quat_alg_elem_t delta;
    ibz_t target_norm;
    quat_alg_t Bpoo;
    const quat_p_extremal_maximal_order_t *order;
    ibz_t n;
    ibz_t equiv_n;

} signing_klpt_param_t;

/** @brief Type for quaternion algebras
 *
 * @typedef eichler_norm_param_t
 *
 * @struct eichler_norm_param
 *
 * the structure used in eichler_norm_param for the call to strong approx
 */
typedef struct eichler_norm_param
{

    quat_alg_elem_t gen_constraint;

    ibz_t target_norm;
    quat_alg_t Bpoo;
    quat_p_extremal_maximal_order_t order;
    ibz_t n;
    quat_order_t right_order;

} eichler_norm_param_t;

/**
 * @}
 */

/** @}
 */

/** @internal
 * @ingroup klpt_tools
 * @{
 */

/**
 * @brief Create an element of a extremal maximal order from its coefficients
 *
 * @param elem Output: the quaternion element
 * @param order the order
 * @param coeffs the vector of 4 ibz coefficients
 * @param Bpoo quaternion algebra
 *
 * elem = x + i*y + j*z + j*i*t
 * where coeffs = [x,y,z,t] and i = order.i, j = order.j
 *
 */
void order_elem_create(quat_alg_elem_t *elem,
                       const quat_p_extremal_maximal_order_t *order,
                       const quat_alg_coord_t *coeffs,
                       const quat_alg_t *Bpoo);

int ibz_cornacchia_special_prime(ibz_t *x,
                                 ibz_t *y,
                                 const ibz_t *n,
                                 const ibz_t *p,
                                 const int exp_adjust);

/** @}
 */

#endif
