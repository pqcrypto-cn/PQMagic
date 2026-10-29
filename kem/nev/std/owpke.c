#include <string.h>
#include "api.h"
#include "owpke.h"
#include "poly.h"
#include "ntt.h"
#include <stdio.h>
#include "randombytes.h"
#include "sample.h"
#include "pack.h"
#include "reduce.h"

#if COMPRESS == 1

void ow_pke_keypair(uint8_t *pk,
					uint8_t *sk)
{
	poly g, f, invg, h;
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
		s = poly_mont2_inverse_judge(&f);
	}
	s = 0;
	while (!s) {
		poly_sample_g(&g, seed, nonce++);
		poly_ntt(&g);
		s = poly_mont2_inverse(&invg, &g);
	}

	poly_mont_mul(&h, &invg, &f);
	poly_reduce(&h);
	poly_caddq(&h);
	poly_caddq(&g);

	// pack sk and pk
	poly_tobytes(sk, &g);
	poly_tobytes(pk, &h);
}

void ow_pke_enc_interal(uint8_t *c,
			   const uint8_t *m,
			   const uint8_t *pk,
			   const uint8_t *rho)
{
	poly h, e, v;

	poly_frombytes(&h, pk);
	poly_get_noisem(&e, m, rho, 1);
	poly_ntt(&e);

	poly_mont_mul(&v, &h, &e);
	poly_reduce(&v);
	poly_invntt(&v);
	poly_getmontgomery(&v);
	poly_caddq(&v);
	// pack ciphertext
	poly_compress(c, &v);
}

void ow_pke_enc(uint8_t *c,
			   const uint8_t *m,
			   const uint8_t *pk)
{
	uint8_t rho[SEED_BYTES];
	randombytes(rho, SEED_BYTES);
	ow_pke_enc_interal(c,m,pk,rho);
}

void ow_pke_dec(uint8_t *m, const uint8_t *c, const uint8_t *sk)
{
	poly g, v, t;
	poly_frombytes(&g, sk);
	poly_decompress(&v, c);
	poly_ntt(&v);
	poly_mont_mul(&t, &g, &v);
	poly_reduce(&t);
	poly_invntt(&t);
	// decode msg
	poly_tomsg(m, &t);
}

#else

void ow_pke_keypair(uint8_t *pk,
                    uint8_t *sk)
{
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

void ow_pke_enc_interal(uint8_t *c,
			   const uint8_t *m,
			   const uint8_t *pk,
			   const uint8_t *rho)
{
	poly h, r, e, v;

	poly_frombytes(&h, pk);
	poly_sample_r(&r, rho, 0);
	poly_get_noisem(&e, m, rho, 1);

	poly_ntt(&r);
	poly_ntt(&e);

	poly_mont_mul(&v, &h, &r);
	poly_add(&v, &v, &e);
	poly_reduce(&v);
	poly_caddq(&v);
	// pack ciphertext
	poly_tobytes(c, &v);
}

void ow_pke_enc(uint8_t *c,
			   const uint8_t *m,
			   const uint8_t *pk)
{
	uint8_t rho[SEED_BYTES];
	randombytes(rho, SEED_BYTES);
	ow_pke_enc_interal(c,m,pk,rho);
}

void ow_pke_dec(uint8_t *m, const uint8_t *c, const uint8_t *sk)
{
	poly f, v, t;
	poly_frombytes(&f, sk);
	poly_frombytes(&v, c);
	poly_mont_mul(&t, &f, &v);
	poly_reduce(&t);
	poly_invntt(&t);
	// decode msg
	poly_tomsg(m, &t);
}
#endif
