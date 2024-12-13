#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"
#include "assert.h"
#include "uintx.h"


// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const spx_ctx *ctx, uint32_t addr[8])
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < SPX_WOTS_W; i++) {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
    }
}


static void encode(unsigned int *out, uint256_t *x, int l, int w)
{

    static int done = 0;
    static uint256_t dp[SPX_WOTS_LEN + 1][(SPX_WOTS_LEN*(SPX_WOTS_W-1)/2) + 1];
    int s = l * (w - 1) / 2;

    if (!done)
    {

        set1_u256(&dp[0][0]);
        for (int i = 1; i <= l; i++)
            for (int j = 0; j <= s; j++)
            {
                set0_u256(&dp[i][j]);
                for (int k = 0; k < w && k <= j; k++)
                    add_u256(&dp[i][j], (const uint256_t *)&dp[i][j], (const uint256_t *)&dp[i - 1][j - k]);
            }

        done = 1;
    }

    for (int i = l - 1; i >= 0; i--)
    {
        int t = -1;
        for (int j = 0; j < w && j <= s; j++)
        {
            if (!less_u256((const uint256_t *)x, (const uint256_t *)&dp[i][s - j]))
            {
                sub_u256(x, (const uint256_t *)x, (const uint256_t *)&dp[i][s - j]);
            }
            else
            {
                t = j;
                break;
            }
        }
        assert(t!=-1);
        
        out[l - 1 - i] = t;
        s -= t;
    }
}

/* Takes a message and derives the matching chain lengths. */
void chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    uint256_t m;

    set0_u256(&m);
    for (int i = 0; i < SPX_N/8; i++)
    {
        m[i] = bytes_to_ull(msg+i*8,8);
    }

    encode(lengths, &m, SPX_WOTS_LEN, SPX_WOTS_W);
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned int lengths[SPX_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(pk + i*SPX_N, sig + i*SPX_N,
                  lengths[i], SPX_WOTS_W - 1 - lengths[i], ctx, addr);
    }
}
