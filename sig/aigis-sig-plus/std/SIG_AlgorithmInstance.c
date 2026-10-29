/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "api.h"

// DRNG_ctx for generating pseudorandom numbers within the SIG scheme
extern DRNG_ctx drng_algorithm;

// The following should be used to get pseudorandom numbers
// get_random_number(&drng_algorithm, random_number, random_number_len_bits);

unsigned long long sig_get_pk_len_bytes()
{
	return SIG_PUBLICKEYBYTES;
}

unsigned long long sig_get_sk_len_bytes()
{
	return SIG_SECRETKEYBYTES;
}

unsigned long long sig_get_sn_len_bytes()
{
	return SIG_BYTES;
}

int sig_keygen(
	unsigned char *pk, unsigned long long *pk_len_bytes,
	unsigned char *sk, unsigned long long *sk_len_bytes)
{
	*pk_len_bytes = SIG_PUBLICKEYBYTES;
	*sk_len_bytes = SIG_SECRETKEYBYTES;
	return msig_keygen(pk, sk);
}

int sig_sign(
	unsigned char *sk, unsigned long long sk_len_bytes,
	unsigned char *m, unsigned long long m_len_bytes,
	unsigned char *sn, unsigned long long *sn_len_bytes)
{
	return msig_sign(sk,
		m, m_len_bytes,
		sn, sn_len_bytes);
}

int sig_verify(
	unsigned char *pk, unsigned long long pk_len_bytes,
	unsigned char *sn, unsigned long long sn_len_bytes,
	unsigned char *m, unsigned long long m_len_bytes)
{
	return msig_verf(pk,
		sn, sn_len_bytes,
		m, m_len_bytes);
}