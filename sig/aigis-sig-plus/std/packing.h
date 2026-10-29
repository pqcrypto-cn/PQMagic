#ifndef PACKING_H
#define PACKING_H

#include "polyvec.h"

void pack_pk(uint8_t pk[PK_SIZE_PACKED],
             const uint8_t rho[SEEDBYTES], const polyveck *t1);

void pack_sk(uint8_t sk[SK_SIZE_PACKED],
	const uint8_t rho[SEEDBYTES],
	const uint8_t key[SEEDBYTES],
	const uint8_t hashpk[CRHBYTES],
	const polyvecl *s1,
	const polyveck *s2,
	const polyveck *t0);

int pack_sig(uint8_t *sm, const polyvecl *z, const uint8_t *cseed, const polyveck *h);

void unpack_pk(uint8_t rho[SEEDBYTES], polyveck *t1, const uint8_t pk[PK_SIZE_PACKED]);

void unpack_sk(uint8_t rho[SEEDBYTES], 
	uint8_t key[SEEDBYTES],
	uint8_t hashpk[CRHBYTES],
	uint8_t s1_table[PARAM_L][PARAM_N * 3],
	s2Word s2_table[PARAM_K][PARAM_N * 3],
	polyveck *t0,
	const uint8_t sk[SK_SIZE_PACKED]);

uint8_t unpack_sig(polyvecl *z, polyveck *h, uint8_t *cseed,
	const uint8_t *sm);
#endif
