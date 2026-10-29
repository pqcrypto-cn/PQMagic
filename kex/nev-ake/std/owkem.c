#include "owkem.h"

#include <string.h>

#include "api.h"
#include "owpke.h"
#include "pack.h"
#include "params.h"
#include "poly.h"
#include "randombytes.h"
#include "sample.h"


void ow_kem_keygen(uint8_t *pk, uint8_t *sk) {
     poly g, f, invf, h;
     uint8_t seed[SEED_BYTES];
     int s;
     uint8_t nonce = 0;
     randombytes(seed, SEED_BYTES);
     Hash(seed, seed, SEED_BYTES);

     s = 0;
     while (!s)
     {
          poly_sample_f(&f, seed, nonce++);
          poly_add_vinv(&f); // f + v^{-1}
          poly_ntt(&f);
          s = poly_mont2_inverse(&invf, &f);
     }
     s = 0;
     while (!s) {
          poly_sample_g(&g, seed, nonce++);
          poly_ntt(&g);
          s = poly_mont2_inverse_judge(&g);
     }

     poly_mont_mul(&h, &invf, &g);
     poly_reduce(&h);
     poly_caddq(&h);
     poly_caddq(&f);

     // pack sk and pk
     poly_tobytes(sk, &f);
     poly_tobytes(pk, &h);
}

void ow_kem_enc_internal(uint8_t *ss, uint8_t *ct, const uint8_t *pk, const uint8_t *rho) {
     poly h, r, m, v;
     poly_frombytes(&h, pk);
     poly_sample_r(&r, rho, 0);
     poly_sample_m(&m, rho, 1);
     poly_extract(ss, &m);

     poly_ntt(&r);
     poly_ntt(&m);

     poly_mont_mul(&v, &h, &r);
     poly_add(&v, &v, &m);
     poly_reduce(&v);
     poly_caddq(&v);
     // pack ciphertext
     poly_tobytes(ct, &v);
}

void ow_kem_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk) {
     uint8_t rho[SEED_BYTES];
     randombytes(rho, SEED_BYTES);
     ow_kem_enc_internal(ss,ct,pk,rho);
}

void ow_kem_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk) {
     poly f, v, t;
     poly_frombytes(&f, sk);
     poly_frombytes(&v, ct);
     poly_mont_mul(&t, &f, &v);
     poly_reduce(&t);
     poly_invntt(&t);
     // decode msg
     poly_tomsg(ss, &t);
}