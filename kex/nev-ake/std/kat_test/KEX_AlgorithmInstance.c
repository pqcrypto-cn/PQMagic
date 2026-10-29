/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include "KEX_AlgorithmInstance.h"
#include "drng.h"
#include "../ake.h"
#include "../params.h"

#include <string.h>

// DRNG_ctx for generating pseudorandom numbers within the KEX protocol
extern DRNG_ctx drng_algorithm;

// The following should be used to get pseudorandom numbers
// get_random_number(&drng_algorithm, random_number, random_number_len_bits);

unsigned long long kex_get_passes_num()
{
	return 2;
}

unsigned long long kex_get_pk_len_bytes()
{
	return AKE_PK_BYTES;
}

unsigned long long kex_get_sk_len_bytes()
{
	return AKE_SK_BYTES;
}

unsigned long long kex_get_sta_len_bytes()
{
	return AKE_ST_BYTES;
}

unsigned long long kex_get_stb_len_bytes()
{
	return AKE_KEY_BYTES;
}

unsigned long long kex_get_ss_len_bytes()
{
	return AKE_KEY_BYTES;
}

unsigned long long kex_get_total_msg_len_bytes()
{
	return AKE_MAX_MESSAGE_BYTES;
}

int kex_init_a(
	unsigned char *pka, unsigned long long *pka_len_bytes,
	unsigned char *ska, unsigned long long *ska_len_bytes,
	unsigned char *sta, unsigned long long *sta_len_bytes)
{
	*pka_len_bytes = AKE_PK_BYTES;
	*ska_len_bytes = AKE_SK_BYTES;
	*sta_len_bytes = AKE_ST_BYTES;
	memset(sta, 0, AKE_ST_BYTES);
	return ake_party_keygen(pka, ska);
}

int kex_init_b(
	unsigned char *pkb, unsigned long long *pkb_len_bytes,
	unsigned char *skb, unsigned long long *skb_len_bytes,
	unsigned char *stb, unsigned long long *stb_len_bytes)
{
	*pkb_len_bytes = AKE_PK_BYTES;
	*skb_len_bytes = AKE_SK_BYTES;
	*stb_len_bytes = AKE_KEY_BYTES;
	memset(stb, 0, AKE_KEY_BYTES);
	return ake_party_keygen(pkb, skb);
}

int kex_generate_pass1_msg_a(
	unsigned char *ska, unsigned long long ska_len_bytes,
	unsigned char *pkb, unsigned long long pkb_len_bytes,
	unsigned char *sta, unsigned long long *sta_len_bytes,
	unsigned char *m1, unsigned long long *m1_len_bytes)
{
	(void)ska_len_bytes;
	(void)pkb_len_bytes;
	ake_init(m1, sta, ska, pkb);
	*sta_len_bytes = AKE_ST_BYTES;
	*m1_len_bytes = AKE_M1_BYTES;
	return 0;
}

int kex_generate_pass2_msg_b(
	unsigned char *skb, unsigned long long skb_len_bytes,
	unsigned char *pka, unsigned long long pka_len_bytes,
	unsigned char *m1, unsigned long long m1_len_bytes,
	unsigned char *stb, unsigned long long *stb_len_bytes,
	unsigned char *m2, unsigned long long *m2_len_bytes)
{
	unsigned char idi[SEED_BYTES] = {0};
	unsigned char idj[SEED_BYTES] = {0};

	(void)skb_len_bytes;
	(void)pka_len_bytes;
	(void)m1_len_bytes;
	ake_der_response(m2, stb, idi, idj, skb, pka, m1);
	*stb_len_bytes = AKE_KEY_BYTES;
	*m2_len_bytes = AKE_M2_BYTES;
	return 1;
}

int kex_generate_pass3_msg_a(
	unsigned char *ska, unsigned long long ska_len_bytes,
	unsigned char *pkb, unsigned long long pkb_len_bytes,
	unsigned char *m2, unsigned long long m2_len_bytes,
	unsigned char *sta, unsigned long long *sta_len_bytes,
	unsigned char *m3, unsigned long long *m3_len_bytes)
{
	(void)ska;
	(void)ska_len_bytes;
	(void)pkb;
	(void)pkb_len_bytes;
	(void)m2;
	(void)m2_len_bytes;
	(void)sta;
	(void)sta_len_bytes;
	(void)m3;
	*m3_len_bytes = 0;
	return -1;
}

/*
int kex_generate_pass4_msg_b(
	unsigned char *skb, unsigned long long skb_len_bytes,
	unsigned char *pka, unsigned long long pka_len_bytes,
	unsigned char *m3, unsigned long long m3_len_bytes,
	unsigned char *stb, unsigned long long *stb_len_bytes,
	unsigned char *m4, unsigned long long *m4_len_bytes)
{
	return 1;
}
int kex_generate_pass5_msg_a(
	unsigned char *ska, unsigned long long ska_len_bytes,
	unsigned char *pkb, unsigned long long pkb_len_bytes,
	unsigned char *m4, unsigned long long m4_len_bytes,
	unsigned char *sta, unsigned long long *sta_len_bytes,
	unsigned char *m5, unsigned long long *m5_len_bytes)
{
	return 1;
}
*/

int kex_derive_ss_a(
	unsigned char *ska, unsigned long long ska_len_bytes,
	unsigned char *pkb, unsigned long long pkb_len_bytes,
	unsigned char *mb, unsigned long long mb_len_bytes,
	unsigned char *sta, unsigned long long sta_len_bytes,
	unsigned char *ssa, unsigned long long *ssa_len_bytes)
{
	unsigned char idi[SEED_BYTES] = {0};
	unsigned char idj[SEED_BYTES] = {0};

	(void)ska_len_bytes;
	(void)pkb_len_bytes;
	(void)mb_len_bytes;
	(void)sta_len_bytes;
	ake_der_init(ssa, idi, idj, ska, pkb, sta, mb);
	*ssa_len_bytes = AKE_KEY_BYTES;
	return 0;
}

int kex_derive_ss_b(
	unsigned char *skb, unsigned long long skb_len_bytes,
	unsigned char *pka, unsigned long long pka_len_bytes,
	unsigned char *ma, unsigned long long ma_len_bytes,
	unsigned char *stb, unsigned long long stb_len_bytes,
	unsigned char *ssb, unsigned long long *ssb_len_bytes)
{
	(void)skb;
	(void)skb_len_bytes;
	(void)pka;
	(void)pka_len_bytes;
	(void)ma;
	(void)ma_len_bytes;
	(void)stb_len_bytes;
	memcpy(ssb, stb, AKE_KEY_BYTES);
	*ssb_len_bytes = AKE_KEY_BYTES;
	return 0;
}
