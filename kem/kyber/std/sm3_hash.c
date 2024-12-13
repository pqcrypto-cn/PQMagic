#include <stddef.h>
#include <stdint.h>
#include "sm3_hash.h"

/*************************************************
* Name:        sm3_256
*
* Description: SM3-256 with non-incremental API
*
* Arguments:   - uint8_t *h:        pointer to output (32 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sm3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
{
  sm3_extended(h, 32, in, inlen);
}

/*************************************************
* Name:        sm3_512
*
* Description: SM3-512 with non-incremental API
*
* Arguments:   - uint8_t *h:        pointer to output (64 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sm3_512(uint8_t *h, const uint8_t *in, size_t inlen)
{
  sm3_extended(h, 64, in, inlen);
}
