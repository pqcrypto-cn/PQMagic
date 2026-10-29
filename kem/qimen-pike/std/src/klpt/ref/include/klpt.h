/** @file
 *
 * @authors Antonin Leroux
 *
 * @brief The norm equation algorithms
 */

#ifndef KLPT_H
#define KLPT_H

#include <intbig.h>
#include <quaternion.h>
#include <klpt_constants.h>
#include <quaternion_data.h>
#include <torsion_constants.h>
#include <stdio.h>

/*************************** Functions *****************************/

/**
 * @brief Representing an integer by the quadratic norm form of a maximal extremal order
 *
 * @param gamma Output: a quaternion element
 * @param n_gamma Output : target norm of gamma (it is also an input, the final value will be a
 * divisor of the initial value)
 * @param Bpoo the quaternion algebra
 *
 * This algorithm finds a primitive quaternion element gamma of n_gamma inside the standard maximal
 * extremal order Failure is possible
 */
int represent_integer(quat_alg_elem_t *gamma, ibz_t *n_gamma, const quat_alg_t *Bpoo);

#endif
