/*
 * Field arithmetic for p765 using modarith unsaturated-radix Montgomery multiplication.
 * Internal representation: 13 limbs x 59-bit unsaturated radix.
 */
#include "modarith_p765.c"
#include <fp.h>

const uint64_t p[NWORDS_FIELD] = {
    0x7fffffffffffffful, 0x0ul, 0x0ul, 0x0ul, 0x216fc48c1000000ul, 0x266aa3bca61d6f5ul, 0x5a6c56c39eee3a6ul, 0x5ed93a2567ac101ul, 0x2e1e6140243d6c8ul, 0x39d142869dd11c8ul, 0x248c078fbabaefcul, 0x3dfaa7dd1edda3bul, 0x1bfa60de9c0419bul
};
const uint64_t ZERO[NWORDS_FIELD] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const uint64_t ONE[NWORDS_FIELD] = {
    0x4ul, 0x0ul, 0x0ul, 0x0ul, 0x7a40edcfc000000ul, 0x6655710d678a42aul, 0x164ea4f18447166ul, 0x49b176a614fbf9ul, 0x47867aff6f0a4ddul, 0x18baf5e588bb8deul, 0x6dcfe1c1151440eul, 0x815608b8489712ul, 0x10167c858fef992ul
};

void fp_add(fp_t *out, const fp_t *a, const fp_t *b) { modadd(*a, *b, *out); }
void fp_sub(fp_t *out, const fp_t *a, const fp_t *b) { modsub(*a, *b, *out); }
void fp_sqr(fp_t *out, const fp_t *a) { modsqr(*a, *out); }
void fp_mul(fp_t *out, const fp_t *a, const fp_t *b) { modmul(*a, *b, *out); }
void fp_tomont(fp_t *out, const fp_t *a) { nres(*a, *out); }
void fp_frommont(fp_t *out, const fp_t *a) { redc(*a, *out); }
void fp_mont_setone(fp_t *out) { modone(*out); }
void fp_neg(fp_t *out, const fp_t *a) { modneg(*a, *out); }
void fp_copy(fp_t *out, const fp_t *a) { modcpy(*a, *out); }
void fp_set_zero(fp_t *a) { modzer(*a); }
void fp_set_one(fp_t *a) { modone(*a); }
void fp_set_small(fp_t *x, const digit_t val) { modzer(*x); (*x)[0] = val; fp_tomont(x, x); }
void fp_half(fp_t *out, const fp_t *a) { modcpy(*a, *out); modhaf(*out); }

void fp_select(fp_t *d, const fp_t *a0, const fp_t *a1, uint32_t ctl) {
    uint64_t cw = (uint64_t) * (int32_t *)&ctl;
    for (unsigned int i = 0; i < NWORDS_FIELD; i++)
        (*d)[i] = (*a0)[i] ^ (cw & ((*a0)[i] ^ (*a1)[i]));
}
void fp_cswap(fp_t *a, fp_t *b, uint32_t ctl) {
    uint64_t cw = (uint64_t) * (int32_t *)&ctl;
    uint64_t t;
    for (unsigned int i = 0; i < NWORDS_FIELD; i++) {
        t = cw & ((*a)[i] ^ (*b)[i]); (*a)[i] ^= t; (*b)[i] ^= t;
    }
}
uint32_t fp_is_equal(const fp_t *a, const fp_t *b) {
    fp_t ta, tb; modcpy(*a, ta); modfsb(ta); modcpy(*b, tb); modfsb(tb);
    return -(uint32_t)modcmp(ta, tb);
}
uint32_t fp_is_zero(const fp_t *a) {
    fp_t ta; modcpy(*a, ta); modfsb(ta);
    return -(uint32_t)modis0(ta);
}
void fp_encode(void *dst, const fp_t *a) {
    char be[FP_NBYTES]; modexp(*a, be);
    uint8_t *out = (uint8_t *)dst;
    for (int i = 0; i < FP_NBYTES; i++) out[i] = (uint8_t)be[FP_NBYTES - 1 - i];
}
void fp_decode_reduce(fp_t *d, const void *src, size_t len) {
    (void)len; const uint8_t *in = (const uint8_t *)src;
    char be[FP_NBYTES];
    for (int i = 0; i < FP_NBYTES; i++) be[i] = (char)in[FP_NBYTES - 1 - i];
    modimp(be, *d);
}
void fp_decode(fp_t *d, const void *src) {
    const uint8_t *in = (const uint8_t *)src; char be[FP_NBYTES];
    for (int i = 0; i < FP_NBYTES; i++) be[i] = (char)in[FP_NBYTES - 1 - i];
    modimp(be, *d);
}
void fp_inv(fp_t *a) { fp_t z; modinv(*a, NULL, z); modcpy(z, *a); }
uint32_t fp_is_square(const fp_t *a) { return -(uint32_t)(modqr(NULL, *a) == 1); }
void fp_sqrt(fp_t *a) {
    fp_t r; modsqrt(*a, NULL, r);
    fp_t neg_r; modneg(r, neg_r); modcmv(modsign(r), neg_r, r);
    modcpy(r, *a);
}
