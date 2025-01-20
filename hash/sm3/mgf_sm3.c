#include "x86-64/include/sm3.h"
#include "include/sm3_extended.h"

static void u32_to_bytes(unsigned char *out, uint32_t in)
{
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

/**
 * mgf1 function based on the SM3 hash function
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
void mgf1_sm3(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen)
{
#ifdef _MSC_VER
    uint8_t *inbuf = (uint8_t*)_alloca((inlen + 4) * sizeof(uint8_t));
#else
    uint8_t inbuf[inlen+4];
#endif
    unsigned char outbuf[SM3_DIGEST_LENGTH];
    uint32_t i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SM3 output.. */
    for (i = 0; (i+1)*SM3_DIGEST_LENGTH <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sm3(inbuf, inlen + 4, out);
        out += SM3_DIGEST_LENGTH;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SM3_DIGEST_LENGTH) {
        u32_to_bytes(inbuf + inlen, i);
        sm3(inbuf, inlen + 4, outbuf);
        memcpy(out, outbuf, outlen - i*SM3_DIGEST_LENGTH);
    }
}
