/*
 * Field arithmetic for p1534 using modarith unsaturated-radix Montgomery multiplication.
 * Internal representation: 26 limbs x 60-bit unsaturated radix.
 */
#include "modarith_p1534.c"
#include <fp.h>

const uint64_t p[NWORDS_FIELD] = {
    0xffffffffffffffful, 0x0ul, 0x0ul, 0x0ul, 0x0ul, 0x0ul, 0x0ul, 0x0ul, 0xf7b456c00000000ul, 0xb1df2a74f745f71ul, 0x530814e9c3615eaul, 0xa281e3cd1244524ul, 0x3afdae93fda6645ul, 0xcb3a5035c534b5ful, 0xf8cd6ed92b85bd0ul, 0xb3e2fa38f5419baul, 0xf81c420b2dfbb3ful, 0xf58123de8fab63eul, 0x3a493432f085476ul, 0x821a8511c268f4cul, 0xf3ede30e07607a2ul, 0xc051219e91bdfbful, 0xf71da19e514541bul, 0xe0e783f6a886397ul, 0x50ed1445554f51cul, 0x22606deb0ul
};
const uint64_t ZERO[NWORDS_FIELD] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
const uint64_t ONE[NWORDS_FIELD] = {
    0x77268a7ul, 0x0ul, 0x0ul, 0x0ul, 0x0ul, 0x0ul, 0x0ul, 0x0ul, 0x449d68c00000000ul, 0x3352c2545c93358ul, 0xd8cab92f2700c19ul, 0x2be71520ccdf166ul, 0xabc07d92c87137cul, 0x8c09925c405f02bul, 0xf00e6cecbe63012ul, 0x75359ebc39ed870ul, 0xf3800404bb1a872ul, 0x5325856499645bcul, 0x99c780c1190b72cul, 0x9c6a89013179891ul, 0xbd20428c7fa56aful, 0x46d18ddb8c4ed8aul, 0x754a2b116f3ffb8ul, 0xb8e9fe4972370dcul, 0xf8e6738e0fde316ul, 0x6a5294f9ul
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
