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
* Name:        data_extended
*
* Description: extend data .
*
* Arguments:   - uint8_t *out:      pointer to output
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
#define data_extended(out, in, inLen)   memcpy(out + 4, in, inLen)


/*************************************************
* Name:        sm3_extended
*
* Description: extend sm3 to support arbitory output len by 
*              perform sm3 multiple times on extended data.
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sm3_extended(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {

    uint32_t nonce = 0;
    uint8_t *in_ext = (uint8_t*)malloc(inlen + 4);
    uint8_t *running_res = (uint8_t*)malloc(outlen + SM3_DIGEST_LENGTH);
    uint8_t *res = running_res;
    int64_t running_outlen = (int64_t)outlen;

    data_extended(in_ext, in, inlen);
    while(running_outlen > 0) {
        add_nonce(in_ext, nonce);

        sm3(in_ext, inlen + 4, running_res);

        running_res += SM3_DIGEST_LENGTH;
        running_outlen -= SM3_DIGEST_LENGTH;
        nonce++;
    }

    memcpy(out, res, outlen);
    free(in_ext);
    free(res);
    in_ext = NULL;
    running_res = NULL;
    res = NULL;
}
