// SPDX-License-Identifier: Apache-2.0

#ifndef rng_h
#define rng_h

/**
 * Randombytes initialization.
 * Initialization may be needed for some random number generators (e.g. CTR-DRBG).
 *
 * @param[in] entropy_input 48 bytes entropy input
 * @param[in] personalization_string Personalization string
 * @param[in] security_strength Security string
 */
void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength);

/**
 * Random byte generation.
 * The caller is responsible to allocate sufficient memory to hold x.
 *
 * @param[out] x Memory to hold the random bytes.
 * @param[in] xlen Number of random bytes to be generated
 * @return int 0 on success, -1 otherwise
 */
int randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
