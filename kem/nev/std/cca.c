#include "api.h"
#include "params.h"
#include "verify.h"
#include "owpke.h"
#include "symmetrics/hashkdf.h"
#include <string.h>
#include <errno.h>

#include "randombytes.h"


int kem_cca_keygen(uint8_t *pk, uint8_t *sk) {
	size_t i;
	ow_pke_keypair(pk, sk);
	for (i = 0; i < KEM_CCA_PK_BYTES; i++) sk[POLY_BYTES + i] = pk[i];
	Hash(sk + KEM_CCA_SK_BYTES - SEED_BYTES, pk, KEM_CCA_PK_BYTES);

	return 0;
}

int kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk) {
	uint8_t kr[2 * SEED_BYTES];
	uint8_t buf[2 * SEED_BYTES];

	randombytes(buf, SEED_BYTES);
	Hash(buf + SEED_BYTES, pk, KEM_CCA_PK_BYTES);
	Hash2(kr, buf, 2 * SEED_BYTES);
	ow_pke_enc_interal(ct, buf, pk, kr + SEED_BYTES);
	for (int i = 0; i < SEED_BYTES; ++i) ss[i] = kr[i];
	return 0;
}

int kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk) {
	size_t i;
	int fail;
	uint8_t cmp[KEM_CCA_CT_BYTES];
	uint8_t buf[3 * SEED_BYTES];
	uint8_t kr[2 * SEED_BYTES];
	const uint8_t *pk = sk + POLY_BYTES;

	ow_pke_dec(buf, ct, sk);
	for (i = 0; i < SEED_BYTES; i++) buf[SEED_BYTES + i] = sk[KEM_CCA_SK_BYTES - SEED_BYTES + i];

	Hash2(kr, buf, 2 * SEED_BYTES);
	ow_pke_enc_interal(cmp, buf, pk, kr + SEED_BYTES);

	fail = verify(ct, cmp, PKE_OW_CT_BYTES);
	if (!fail) {
		for (i = 0; i < SEED_BYTES; ++i) ss[i] = kr[i];
	}
	return fail;
}

void pke_cca_keygen(uint8_t *pk, uint8_t *sk) {
	size_t i;
	ow_pke_keypair(pk, sk);
	for (i = 0; i < KEM_CCA_PK_BYTES; i++) sk[POLY_BYTES + i] = pk[i];
	Hash(sk + KEM_CCA_SK_BYTES - SEED_BYTES, pk, PKE_CCA_PK_BYTES);
}

void pke_cca_enc(uint8_t *ct, const uint8_t *mu, const uint8_t *pk) {
	uint8_t buf[3 * SEED_BYTES];
	uint8_t rho[SEED_BYTES];

	randombytes(buf, SEED_BYTES);
	Hash(buf + 2 * SEED_BYTES, buf, SEED_BYTES);//Need to change to H3
	for (int i = 0; i < SEED_BYTES; ++i) buf[2 * SEED_BYTES + i] ^= mu[i];
	Hash(buf + SEED_BYTES, pk, PKE_CCA_PK_BYTES);
	Hash(rho, buf, 3 * SEED_BYTES);//Need to change to H2
	ow_pke_enc_interal(ct, buf, pk, rho);

	for (int i = 0; i < SEED_BYTES; ++i) ct[PKE_OW_CT_BYTES + i] = buf[2 * SEED_BYTES + i];
}

int  pke_cca_dec(uint8_t *mu, const uint8_t *ct, const uint8_t *sk) {
	size_t i;
	int fail;
	uint8_t cmp[PKE_OW_CT_BYTES];
	uint8_t buf[3 * SEED_BYTES];
	uint8_t rho[SEED_BYTES];
	const uint8_t *pk = sk + POLY_BYTES;
	const uint8_t *c2 = ct + PKE_OW_CT_BYTES;

	ow_pke_dec(buf, ct, sk);
	for (i = 0; i < SEED_BYTES; i++) buf[SEED_BYTES + i] = sk[PKE_CCA_SK_BYTES - SEED_BYTES + i];
	for (i = 0; i < SEED_BYTES; i++) buf[2 * SEED_BYTES +i] = c2[i];
	Hash(rho, buf, 3 * SEED_BYTES);//Need to change to H2

	ow_pke_enc_interal(cmp, buf, pk, rho);
	fail = verify(ct, cmp, PKE_OW_CT_BYTES);
	if (!fail) {
		Hash(mu, buf, SEED_BYTES);//Need to change to H3
		for (i = 0; i < SEED_BYTES; ++i) mu[i] ^= c2[i];
	}
	return fail;
}
