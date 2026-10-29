/** @file
 *
 * @authors Antonin Leroux
 *
 * @brief The id2iso algorithms
 */

#ifndef ID2ISO_H
#define ID2ISO_H

#include <intbig.h>
#include <quaternion.h>
#include <klpt.h>
#include <ec.h>

/** @defgroup id2iso_id2iso Ideal to isogeny conversion
 * @{
 */

/** @defgroup id2iso_iso_types Types for isogenies needed for the id2iso
 * @{
 */

/** @brief Type for long chain of two isogenies
 *
 * @typedef id2iso_long_two_isog
 *
 * Represented as a vector ec_isog_even_t
 */
typedef struct id2iso_long_two_isog
{
    unsigned short length; ///< the number of smaller two isogeny chains
    ec_isog_even_t *chain; ///< the chain of two isogeny
} id2iso_long_two_isog_t;

/** @brief Type for compressed long chain of two isogenies
 *
 * @typedef id2iso_compressed_long_two_isog
 *
 * Represented as a vector of intbig
 */
typedef struct id2iso_compressed_long_two_isog
{
    unsigned short length;        ///< the number of smaller two isogeny chains
    ibz_t *zip_chain;             ///< the chain of two isogeny, compressed
    unsigned char bit_first_step; ///< the bit for the first step
} id2iso_compressed_long_two_isog_t;

/** @}
 */

/*************************** Functions *****************************/

/** @defgroup id2iso_others Other functions needed for id2iso
 * @{
 */

/**
 * @brief Translating an ideal of odd norm dividing p²-1 into the corresponding isogeny
 *
 * @param isog Output : the output isogeny
 * @param basis_minus : a basis of ec points
 * @param basis_plus : a basis of ec points
 * @param domain : an elliptic curve
 * @param lideal_input : O0-ideal corresponding to the ideal to be translated
 *
 * compute  the isogeny starting from domain corresponding to ideal_input
 * the coefficients extracted from the ideal are to be applied to basis_minus and basis_plus to
 * compute the kernel of the isogeny.
 *
 */

void id2iso_ideal_to_isogeny_odd(ec_isog_odd_t *isog,
                                 const ec_curve_t *domain,
                                 const ec_basis_t *basis_plus,
                                 const ec_basis_t *basis_minus,
                                 const quat_left_ideal_t *lideal_input);

// helper function to apply some 2x2 matrix on a basis of E[2^TORSION_PLUS_EVEN_POWER]
// works in place
void matrix_application_even_basis(ec_basis_t *P, const ec_curve_t *E, ibz_mat_2x2_t *mat, int f);
// helper function to apply some endomorphism of E on a basis of E[2^TORSION_PLUS_EVEN_POWER]
// works in place
void endomorphism_application_even_basis(ec_basis_t *P,
                                         const ec_curve_t *E,
                                         quat_alg_elem_t *theta,
                                         int f);                                   
#endif
