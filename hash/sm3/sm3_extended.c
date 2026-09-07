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

#define add_nonce(out, nonce)                   \
    do{                                         \
        out[0] = (uint8_t)(nonce >> 24) & 0xff; \
        out[1] = (uint8_t)(nonce >> 16) & 0xff; \
        out[2] = (uint8_t)(nonce >> 8) & 0xff;  \
        out[3] = (uint8_t)(nonce) & 0xff;       \
    }while(0)

/*************************************************
* Name:        sm3_extended
*
* Description: extend sm3 to support arbitory output len by
*              perform sm3 multiple times on extended data.
*
*              The counter and the message are fed to SM3 as two successive
*              updates rather than copied into one heap buffer, and each digest
*              block is produced into a stack buffer and copied out, so this
*              function performs no allocation and cannot fail.
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sm3_extended(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {

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
