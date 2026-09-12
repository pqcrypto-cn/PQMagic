#if                             \
    (defined(__i386__))     ||  \
    (defined(__x86_64__))   ||  \
    (defined(__arm__))      ||  \
    (defined(__aarch64__))
#include "x86-64/include/sm3.h"
#else
#error "Now only support for ref version."
#endif
#include "include/sm3_extended.h"
#include <stdlib.h>

#define add_nonce(out, nonce)                   \
    do{                                         \
        out[0] = (uint8_t)(nonce >> 24) & 0xff; \
        out[1] = (uint8_t)(nonce >> 16) & 0xff; \
        out[2] = (uint8_t)(nonce >> 8) & 0xff;  \
        out[3] = (uint8_t)(nonce) & 0xff;       \
    }while(0)

static int buffers_overlap(const uint8_t *a, size_t alen,
                           const uint8_t *b, size_t blen) {
    uintptr_t xa = (uintptr_t)a;
    uintptr_t xb = (uintptr_t)b;

    if(alen == 0 || blen == 0) {
        return 0;
    }
    return xa < xb + blen && xb < xa + alen;
}

/* Write SM3(counter || in) blocks into out. `out` must not overlap `in`. */
static void sm3_extended_into(uint8_t *out, size_t outlen,
                              const uint8_t *in, size_t inlen) {
    uint32_t nonce = 0;
    uint8_t counter[4];
    uint8_t block[SM3_DIGEST_LENGTH];
    size_t done = 0;

    while(done < outlen) {
        SM3_CTX ctx;
        size_t take = outlen - done;

        add_nonce(counter, nonce);

        sm3_init(&ctx);
        sm3_update(&ctx, counter, 4);
        sm3_update(&ctx, in, inlen);
        sm3_final(&ctx, block);

        if(take > SM3_DIGEST_LENGTH) {
            take = SM3_DIGEST_LENGTH;
        }
        memcpy(out + done, block, take);

        done += take;
        nonce++;
        memset(&ctx, 0, sizeof(SM3_CTX));
    }

    memset(block, 0, sizeof(block));
}

/*************************************************
* Name:        sm3_extended
*
* Description: extend sm3 to support arbitory output len by
*              perform sm3 multiple times on extended data.
*
*              Each output block is SM3(big-endian counter || in), with the
*              counter starting at 0. If out overlaps in and more than one
*              digest is written, later rounds would re-read a mutated input,
*              so the shorter of the two ranges is snapshotted first.
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sm3_extended(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    uint8_t *scratch = NULL;
    uint8_t *dst = out;
    const uint8_t *src = in;

    if(outlen == 0) {
        return;
    }

    if(outlen > SM3_DIGEST_LENGTH &&
       buffers_overlap(out, outlen, in, inlen)) {
        if(outlen <= inlen) {
            scratch = (uint8_t*)malloc(outlen);
            dst = scratch;
        } else {
            scratch = (uint8_t*)malloc(inlen);
            if(scratch != NULL) {
                memcpy(scratch, in, inlen);
            }
            src = scratch;
        }
        if(scratch == NULL) {
            return;
        }
    }

    sm3_extended_into(dst, outlen, src, inlen);

    if(dst != out) {
        memcpy(out, dst, outlen);
    }
    free(scratch);
}
