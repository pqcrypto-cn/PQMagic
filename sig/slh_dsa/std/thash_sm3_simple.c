#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"
#include "spx_sm3.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    SPX_VLA(unsigned char, buf, SPX_N + SPX_SM3_ADDR_BYTES + inblocks*SPX_N);
    unsigned char outbuf[SPX_SM3_OUTPUT_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SM3_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_SM3_ADDR_BYTES, in, inblocks * SPX_N);

    // SPX_N is less then SPX_SM3_OUTPUT_BYTES, no need extend.
    // sm3_extended(out, SPX_N, buf, SPX_N + SPX_SM3_ADDR_BYTES + inblocks*SPX_N);
    sm3(buf, SPX_N + SPX_SM3_ADDR_BYTES + inblocks*SPX_N, outbuf);
    memcpy(out, outbuf, SPX_N);
}
