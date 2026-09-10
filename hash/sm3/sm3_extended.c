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
#include <stdint.h>
#include <stdlib.h>

#define add_nonce(out, nonce)                   \
    do{                                         \
        out[0] = (uint8_t)(nonce >> 24) & 0xff; \
        out[1] = (uint8_t)(nonce >> 16) & 0xff; \
        out[2] = (uint8_t)(nonce >> 8) & 0xff;  \
        out[3] = (uint8_t)(nonce) & 0xff;       \
    }while(0)

/* Large enough for every current in-place call site (max 128 bytes). */
#define SM3_EXTENDED_STACK 256

/*************************************************
* Name:        buffers_overlap
*
* Description: return 1 if the two byte ranges share any address.
**************************************************/
static int buffers_overlap(const uint8_t *a, size_t alen,
                           const uint8_t *b, size_t blen) {
    uintptr_t xa = (uintptr_t)a;
    uintptr_t xb = (uintptr_t)b;

    if(alen == 0 || blen == 0) {
        return 0;
    }
    return xa < xb + blen && xb < xa + alen;
}

/*************************************************
* Name:        sm3_extended_from
*
* Description: write sm3_extended output assuming `out` does not overlap `in`.
**************************************************/
static void sm3_extended_from(uint8_t *out, size_t outlen,
                              const uint8_t *in, size_t inlen) {
    uint32_t nonce = 0;
    uint8_t counter[4];
    uint8_t block[SM3_DIGEST_LENGTH];
    size_t done = 0;

    while(done < outlen) {
        SM3_CTX ctx;

        add_nonce(counter, nonce);

        sm3_init(&ctx);
        sm3_update(&ctx, counter, 4);
        sm3_update(&ctx, in, inlen);
        sm3_final(&ctx, block);

        size_t take = outlen - done;
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
*              The counter and the message are fed to SM3 as two successive
*              updates rather than copied into one heap buffer, and each digest
*              block is produced into a stack buffer and copied out.
*
*              If out overlaps in and more than one digest block is requested,
*              a snapshot of the shorter range is used so later rounds still
*              hash the original input. Disjoint buffers and single-block
*              outputs perform no allocation.
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sm3_extended(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    uint8_t stack[SM3_EXTENDED_STACK];
    uint8_t *tmp = NULL;

    if(outlen == 0) {
        return;
    }

    if(outlen <= SM3_DIGEST_LENGTH ||
       !buffers_overlap(out, outlen, in, inlen)) {
        sm3_extended_from(out, outlen, in, inlen);
        return;
    }

    if(outlen <= inlen) {
        tmp = (outlen <= SM3_EXTENDED_STACK) ? stack : (uint8_t*)malloc(outlen);
        if(tmp == NULL) {
            return;
        }
        sm3_extended_from(tmp, outlen, in, inlen);
        memcpy(out, tmp, outlen);
    } else {
        tmp = (inlen <= SM3_EXTENDED_STACK) ? stack : (uint8_t*)malloc(inlen);
        if(tmp == NULL) {
            return;
        }
        memcpy(tmp, in, inlen);
        sm3_extended_from(out, outlen, tmp, inlen);
    }

    if(tmp != stack) {
        free(tmp);
    }
}
