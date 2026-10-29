#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "packing.h"

/*************************************************
* pack the public key pk, 
* where pk = rho|t1
**************************************************/
void pack_pk(uint8_t pk[PK_SIZE_PACKED],
             const uint8_t rho[SEEDBYTES],
             const polyveck *t1)
{
  int i;
  for(i = 0; i < SEEDBYTES; ++i)
    pk[i] = rho[i];
  pk += SEEDBYTES;

  for (i = 0; i < PARAM_K; ++i)
	  polyt1_pack(pk + i * POLT1_SIZE_PACKED, t1->vec + i);
}
void unpack_pk(uint8_t rho[SEEDBYTES],polyveck *t1,const uint8_t pk[PK_SIZE_PACKED])
{
  int i;

  for(i = 0; i < SEEDBYTES; ++i)
    rho[i] = pk[i];
  pk += SEEDBYTES;

  for(i = 0; i < PARAM_K; ++i)
    polyt1_unpack(t1->vec+i, pk + i*POLT1_SIZE_PACKED);
}

/*************************************************
* pack the secret key sk, 
* where sk = rho|key|hash(pk)|s1|s2|t0
**************************************************/
void pack_sk(uint8_t sk[SK_SIZE_PACKED],
	const uint8_t rho[SEEDBYTES],
	const uint8_t key[SEEDBYTES],
	const uint8_t hashpk[CRHBYTES],
	const polyvecl *s1,
	const polyveck *s2,
	const polyveck *t0)
{
	int i;

	for (i = 0; i <SEEDBYTES; ++i)
		sk[i] = rho[i];
	sk += SEEDBYTES;
	for (i = 0; i < SEEDBYTES; ++i)
		sk[i] = key[i];
	sk += SEEDBYTES;
	for (i = 0; i < CRHBYTES; ++i)
		sk[i] = hashpk[i];
	sk += CRHBYTES;

	for (i = 0; i < PARAM_L; ++i)
		polyeta1_pack(sk + i * POLETA1_SIZE_PACKED, s1->vec + i);
	sk += PARAM_L * POLETA1_SIZE_PACKED;

	for (i = 0; i < PARAM_K; ++i)
		polyeta2_pack(sk + i * POLETA2_SIZE_PACKED, s2->vec + i);
	sk += PARAM_K * POLETA2_SIZE_PACKED;

	for (i = 0; i < PARAM_K; ++i)
		polyt0_pack(sk + i * POLT0_SIZE_PACKED, t0->vec + i);
}


static void s1_unpack(uint8_t s1_table[PARAM_N * 3], uint8_t *a) {
	const int32_t eta1x2 = 2 * ETA1;
#if ETA1 == 1
	for (int j = 0; j < PARAM_N / 4; ++j) {
		s1_table[4 * j + 2 * PARAM_N + 0] = s1_table[4 * j + 0]  =  a[j] & 0x03;
		s1_table[4 * j + 2 * PARAM_N + 1] = s1_table[4 * j + 1]  = (a[j] >> 2) & 0x03;
		s1_table[4 * j + 2 * PARAM_N + 2] = s1_table[4 * j + 2]  = (a[j] >> 4) & 0x03;
		s1_table[4 * j + 2 * PARAM_N + 3] = s1_table[4 * j + 3]  = (a[j] >> 6) & 0x03;

		s1_table[4 * j +  PARAM_N + 0] = eta1x2 - s1_table[4 * j + 0];
		s1_table[4 * j +  PARAM_N + 1] = eta1x2 - s1_table[4 * j + 1];
		s1_table[4 * j +  PARAM_N + 2] = eta1x2 - s1_table[4 * j + 2];
		s1_table[4 * j +  PARAM_N + 3] = eta1x2 - s1_table[4 * j + 3];
	}
#elif ETA1 == 2
	int pos;
	for (int j = 0; j < PARAM_N / 8; ++j) {
		pos = 3 * j;
		s1_table[8 * j + 2 * PARAM_N + 0] = s1_table[8 * j + 0]  =  a[pos] & 0x07;
		s1_table[8 * j + 2 * PARAM_N + 1] = s1_table[8 * j + 1]  = (a[pos] >> 3) & 0x07;
		s1_table[8 * j + 2 * PARAM_N + 2] = s1_table[8 * j + 2]  = ((a[pos] >> 6) | (a[pos + 1] << 2)) & 0x07;
		s1_table[8 * j + 2 * PARAM_N + 3] = s1_table[8 * j + 3]  = (a[pos + 1] >> 1) & 0x07;
		s1_table[8 * j + 2 * PARAM_N + 4] = s1_table[8 * j + 4]  = (a[pos + 1] >> 4) & 0x07;
		s1_table[8 * j + 2 * PARAM_N + 5] = s1_table[8 * j + 5]  = ((a[pos + 1] >> 7) | (a[pos + 2] << 1)) & 0x07;
		s1_table[8 * j + 2 * PARAM_N + 6] = s1_table[8 * j + 6]  = (a[pos + 2] >> 2) & 0x07;
		s1_table[8 * j + 2 * PARAM_N + 7] = s1_table[8 * j + 7]  = (a[pos + 2] >> 5) & 0x07;

		s1_table[8 * j +  PARAM_N + 0] = eta1x2 - s1_table[8 * j + 0];
		s1_table[8 * j +  PARAM_N + 1] = eta1x2 - s1_table[8 * j + 1];
		s1_table[8 * j +  PARAM_N + 2] = eta1x2 - s1_table[8 * j + 2];
		s1_table[8 * j +  PARAM_N + 3] = eta1x2 - s1_table[8 * j + 3];
		s1_table[8 * j +  PARAM_N + 4] = eta1x2 - s1_table[8 * j + 4];
		s1_table[8 * j +  PARAM_N + 5] = eta1x2 - s1_table[8 * j + 5];
		s1_table[8 * j +  PARAM_N + 6] = eta1x2 - s1_table[8 * j + 6];
		s1_table[8 * j +  PARAM_N + 7] = eta1x2 - s1_table[8 * j + 7];
	}
#endif
}


static void s2_unpack(s2Word s2_table[PARAM_N * 3], uint8_t *a) {
	const int32_t eta2x2 = 2 * ETA2;
#if ETA2 == 5
	for (int i = 0; i < PARAM_N / 4; ++i) {
		s2_table[4 * i + 2 * PARAM_N + 0] = s2_table[4 * i + 0] = a[2 * i] & 0x0F;
		s2_table[4 * i + 2 * PARAM_N + 1] = s2_table[4 * i + 1] = (a[2 * i] >> 4);
		s2_table[4 * i + 2 * PARAM_N + 2] = s2_table[4 * i + 2] = a[2 * i + 1] & 0x0F;
		s2_table[4 * i + 2 * PARAM_N + 3] = s2_table[4 * i + 3] = (a[2 * i + 1] >> 4);

		s2_table[4 * i + PARAM_N + 0] = eta2x2 - s2_table[4 * i + 0];
		s2_table[4 * i + PARAM_N + 1] = eta2x2 - s2_table[4 * i + 1];
		s2_table[4 * i + PARAM_N + 2] = eta2x2 - s2_table[4 * i + 2];
		s2_table[4 * i + PARAM_N + 3] = eta2x2 - s2_table[4 * i + 3];
	}
#elif ETA2 == 1
	for (int i = 0; i < PARAM_N / 4; ++i) {
		s2_table[4 * i + 2 * PARAM_N + 0] = s2_table[4 * i + 0] = a[i] & 0x03;
		s2_table[4 * i + 2 * PARAM_N + 1] = s2_table[4 * i + 1] = (a[i] >> 2) & 0x03;
		s2_table[4 * i + 2 * PARAM_N + 2] = s2_table[4 * i + 2] = (a[i] >> 4) & 0x03;
		s2_table[4 * i + 2 * PARAM_N + 3] = s2_table[4 * i + 3] = (a[i] >> 6) & 0x03;

		s2_table[4 * i + PARAM_N + 0] = eta2x2 - s2_table[4 * i + 0];
		s2_table[4 * i + PARAM_N + 1] = eta2x2 - s2_table[4 * i + 1];
		s2_table[4 * i + PARAM_N + 2] = eta2x2 - s2_table[4 * i + 2];
		s2_table[4 * i + PARAM_N + 3] = eta2x2 - s2_table[4 * i + 3];
	}
#elif ETA2 == 2
	int pos;
	for (int j = 0; j < PARAM_N / 8; ++j) {
		pos = 3 * j;
		s2_table[8 * j + 2 * PARAM_N + 0] = s2_table[8 * j + 0]  =  a[pos] & 0x07;
		s2_table[8 * j + 2 * PARAM_N + 1] = s2_table[8 * j + 1]  = (a[pos] >> 3) & 0x07;
		s2_table[8 * j + 2 * PARAM_N + 2] = s2_table[8 * j + 2]  = ((a[pos] >> 6) | (a[pos + 1] << 2)) & 0x07;
		s2_table[8 * j + 2 * PARAM_N + 3] = s2_table[8 * j + 3]  = (a[pos + 1] >> 1) & 0x07;
		s2_table[8 * j + 2 * PARAM_N + 4] = s2_table[8 * j + 4]  = (a[pos + 1] >> 4) & 0x07;
		s2_table[8 * j + 2 * PARAM_N + 5] = s2_table[8 * j + 5]  = ((a[pos + 1] >> 7) | (a[pos + 2] << 1)) & 0x07;
		s2_table[8 * j + 2 * PARAM_N + 6] = s2_table[8 * j + 6]  = (a[pos + 2] >> 2) & 0x07;
		s2_table[8 * j + 2 * PARAM_N + 7] = s2_table[8 * j + 7]  = (a[pos + 2] >> 5) & 0x07;

		s2_table[8 * j +  PARAM_N + 0] = eta2x2 - s2_table[8 * j + 0];
		s2_table[8 * j +  PARAM_N + 1] = eta2x2 - s2_table[8 * j + 1];
		s2_table[8 * j +  PARAM_N + 2] = eta2x2 - s2_table[8 * j + 2];
		s2_table[8 * j +  PARAM_N + 3] = eta2x2 - s2_table[8 * j + 3];
		s2_table[8 * j +  PARAM_N + 4] = eta2x2 - s2_table[8 * j + 4];
		s2_table[8 * j +  PARAM_N + 5] = eta2x2 - s2_table[8 * j + 5];
		s2_table[8 * j +  PARAM_N + 6] = eta2x2 - s2_table[8 * j + 6];
		s2_table[8 * j +  PARAM_N + 7] = eta2x2 - s2_table[8 * j + 7];
	}
#endif
}

void unpack_sk(uint8_t rho[SEEDBYTES], 
	uint8_t key[SEEDBYTES],
	uint8_t hashpk[CRHBYTES],
	uint8_t s1_table[PARAM_L][PARAM_N * 3],
	s2Word s2_table[PARAM_K][PARAM_N * 3],
	polyveck *t0,
	const uint8_t sk[SK_SIZE_PACKED])
{
	int i;

	for (i = 0; i <SEEDBYTES; ++i)
		rho[i] = sk[i];
	sk += SEEDBYTES;
	for (i = 0; i <SEEDBYTES; ++i)
		key[i] = sk[i];
	sk += SEEDBYTES;
	for (i = 0; i <CRHBYTES; ++i)
		hashpk[i] = sk[i];

	sk += CRHBYTES;

	for (int j = 0; j < PARAM_L; j++)
		s1_unpack(s1_table[j],sk + j * POLETA1_SIZE_PACKED);
	sk += PARAM_L * POLETA1_SIZE_PACKED;

	for (i = 0; i < PARAM_K; ++i)
		s2_unpack(s2_table[i], sk + i * POLETA2_SIZE_PACKED);
	sk += PARAM_K * POLETA2_SIZE_PACKED;

	for (i = 0; i < PARAM_K; ++i)
		polyt0_unpack(t0->vec + i, sk + i * POLT0_SIZE_PACKED);
}

static uint8_t pack4bits(uint8_t *sm, int *t, int k)
{
	int i;
	for (i = 0; i < k >> 1; i++)
		sm[i] = t[2 * i] | (t[2 * i + 1] << 4);
	if ((k & 1) != 0)
		sm[i] = t[2 * i];
	return (k + 1) >> 1;
}
int unpack4bits(int *t, uint8_t *sm, int k)
{
	int i;
	for (i = 0; i < k >> 1; i++)
	{
		t[2 * i] = sm[i] & 0xF;
		t[2 * i + 1] = sm[i] >> 4;
	}
	if ((k & 1) == 1)
		t[k-1] = sm[i] & 0xF;

	return (k + 1) >> 1;
}

static int pack6bits(uint8_t *sm, int *t, int k)
{
	int i;
	for (i = 0; i < k / 4; i++)
	{
		sm[3 * i] = t[4 * i] | (t[4 * i + 1] << 6);
		sm[3 * i + 1] = (t[4 * i + 1] >> 2) | (t[4 * i + 2] << 4);
		sm[3 * i + 2] = (t[4 * i + 2] >> 4) | (t[4 * i + 3] << 2);
	}
	switch (k % 4)
	{
	case 1:
		sm[3 * i] = t[4 * i];
		break;
	case 2:
		sm[3 * i] = t[4 * i] | (t[4 * i + 1] << 6);
		sm[3 * i + 1] = (t[4 * i + 1] >> 2);
		break;
	case 3:
		sm[3 * i] = t[4 * i] | (t[4 * i + 1] << 6);
		sm[3 * i + 1] = (t[4 * i + 1] >> 2) | (t[4 * i + 2] << 4);
		sm[3 * i + 2] = (t[4 * i + 2] >> 4);
		break;
	}
	return (k * 6 + 7) / 8;
}

static int unpack6bits(int *t, uint8_t *sm, int k)
{
	int i;
	for (i = 0; i < k / 4; i++)
	{
		t[4 * i] = sm[3 * i] & 0x3F;
		t[4 * i + 1] = (sm[3 * i] >> 6) | ((sm[3 * i + 1] & 0xF) << 2);
		t[4 * i + 2] = (sm[3 * i + 1] >> 4) | ((sm[3 * i + 2] & 0x3) << 4);
		t[4 * i + 3] = sm[3 * i + 2] >> 2;
	}
	switch (k % 4)
	{
	case 1:
		t[4 * i] = sm[3 * i] & 0x3F;
		break;
	case 2:
		t[4 * i] = sm[3 * i] & 0x3F;
		t[4 * i + 1] = (sm[3 * i] >> 6) | ((sm[3 * i + 1] & 0xF) << 2);
		break;
	case 3:
		t[4 * i] = sm[3 * i] & 0x3F;
		t[4 * i + 1] = (sm[3 * i] >> 6) | ((sm[3 * i + 1] & 0xF) << 2);
		t[4 * i + 2] = (sm[3 * i + 1] >> 4) | ((sm[3 * i + 2] & 0x3) << 4);
		break;
	}
	return (k * 6 + 7) / 8;
}

static int pack_h(uint8_t *sm, const polyveck *h)
{
	int i, j, k, r;
	int len;
	int pos[OMEGA];
	int t[PARAM_N / SEC * PARAM_K];
	int start;
	k = 0;
	uint8_t max = 0;
	for (i = 0; i < PARAM_K; ++i)
	{
		for (j = 0; j < PARAM_N / SEC; j++)
		{
			start = k;
			for (r = 0; r < SEC; r++)
				if (h->vec[i].coeffs[SEC * j + r])
					pos[k++] = r;
			t[PARAM_N / SEC * i + j] = k - start;
			if (t[PARAM_N / SEC * i + j] != 0)
				max = PARAM_N / SEC * i + j + 1;
		}
	}
	sm[0] = max;
	sm += 1;
	len = pack4bits(sm, t, max);
	sm += len;
	len += pack6bits(sm, pos, k) + 1;
	return len;
}

uint8_t unpack_h(polyveck *h, uint8_t *sm)
{
	int i,j,k, r;
	int pos[OMEGA];
	int t[PARAM_K * PARAM_N / SEC];
	int start;
	int shift = 0;
	k = 0;
	int max = sm[0];

	for (int i = 0; i < PARAM_K; i++)
		for (int j = 0; j < PARAM_N; j++)
			h->vec[i].coeffs[j] = 0;

	sm += 1;
	unpack4bits(t, sm, max);
	sm += unpack4bits(t, sm, max);

	k = 0;
	for (i = 0; i < max; i++)
		k += t[i];

	unpack6bits(pos, sm, k);

	r = 0;
	for (k = 0; k < max; k++)
	{
		i = k / (PARAM_N / SEC);
		j = k % (PARAM_N / SEC);
		for (start = 0; start < t[k]; start++)
			h->vec[i].coeffs[SEC * j + pos[r++]] = 1;
	}

	return 0;
}

/*************************************************
* pack the signature sm, 
* where sm = z|h|c
**************************************************/
int pack_sig(uint8_t *sm, const polyvecl *z, const uint8_t *cseed, const polyveck *h)
{
	int32_t i, j, k, pos;
	int sig_len;
	
	for (i = 0; i < PARAM_L; ++i)
		polyz_pack(sm + i * POLZ_SIZE_PACKED, z->vec + i);
	sm += PARAM_L * POLZ_SIZE_PACKED;

	/* Encode cseed */
	for (i = 0; i < SEEDBYTES; i++)
		sm[i] = cseed[i];
	sm += SEEDBYTES;

	//pack h
	sig_len = pack_h(sm, h);
	sig_len += PARAM_L * POLZ_SIZE_PACKED + SEEDBYTES;

	return sig_len;
}
uint8_t unpack_sig(polyvecl *z, polyveck *h, uint8_t *cseed,
	const uint8_t *sm)
{
	int32_t i, j, k, pos;
	uint8_t b;

	for (i = 0; i < PARAM_L; ++i)
		polyz_unpack(z->vec + i, sm + i * POLZ_SIZE_PACKED);
	sm += PARAM_L * POLZ_SIZE_PACKED;

	/* Decode cseed */
	for (i = 0; i < SEEDBYTES; ++i)
		cseed[i] = sm[i];
	sm += SEEDBYTES;

	/* Decode h */
	b = unpack_h(h, sm);

	return b;
}
