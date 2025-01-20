#ifndef SM3_EXTENDED_H
#define SM3_EXTENDED_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*************************************************
* Name:        sm3_extended
*
* Description: extend sm3 to support arbitrary output len by 
*              perform sm3 multiple times on extended data.
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sm3_extended(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/**
 * mgf1 function based on the SM3 hash function
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
void mgf1_sm3(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#endif
