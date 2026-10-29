/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define SEED_LEN_BYTES 64
#define KAT_SIG_SUCCESS 0
#define KAT_ALGORITHM_INSTANCE_NAME_INVALID -1
#define KAT_FILE_OPERATE_FAILED -2
#define KAT_SIG_CRYPTO_FAILURE -3
#define KAT_MEMORY_ALLOCATION_FAILED -4

static int validate_algorithm_instance_name(const char *algorithm);
static int create_directory(const char *path);
static void fprintlen(FILE *file_output, char *identifier, unsigned long long len);
static void fprintstr(FILE *file_output, char *identifier, unsigned char *msg, unsigned long long len);

// DRNG_ctx for generating pseudorandom numbers within the SIG scheme
DRNG_ctx drng_algorithm;

/****************output KAT_SIG_AlgorithmInstance.txt****************/
int main()
{
	unsigned char *nonce1;
	unsigned char *nonce2;
	// DRNG_ctx for generating seed
	DRNG_ctx drng_seed;
	// DRNG_ctx for generating message
	DRNG_ctx drng_msg;
	char algoname_output[96];
	FILE *file_output;
	unsigned char *seed, *m, *sn, *pk, *sk;
	unsigned long long pk_len_bytes, sk_len_bytes, sn_len_bytes;
	int m_len_bytes = 56;
	int rtn;
	if (validate_algorithm_instance_name(ALGORITHM_INSTANCE))
	{
		fprintf(stderr, "ERROR: Invalid algorithm instance name. Only letters, numbers, '-' or '_' are permitted.\n");
		return KAT_ALGORITHM_INSTANCE_NAME_INVALID;
	}
	// init drng_seed using nonce1
	nonce1 = (unsigned char *)calloc(SEED_LEN_BYTES, sizeof(unsigned char));
	for (int i = 0; i < SEED_LEN_BYTES / 4; i++)
	{
		memcpy(nonce1 + 4 * i, "seed", 4);
	}
	init_random_number(&drng_seed, nonce1, SEED_LEN_BYTES);
	// init drng_msg using nonce2
	nonce2 = (unsigned char *)calloc(SEED_LEN_BYTES, sizeof(unsigned char));
	for (int i = 0; i < SEED_LEN_BYTES / 3; i++)
	{
		memcpy(nonce2 + 3 * i, "msg", 3);
	}
	memcpy(nonce2 + SEED_LEN_BYTES - 1, "m", 1);
	init_random_number(&drng_msg, nonce2, SEED_LEN_BYTES);
	// open KAT_SIG_AlgorithmInstance.txt
	const char *dir_name = "output";
	char file_path[128] = "";
	sprintf(algoname_output, "KAT_SIG_%s.txt", ALGORITHM_INSTANCE);
	sprintf(file_path, "%s/%s", dir_name, algoname_output);
	if (0 != create_directory(dir_name))
	{
		fprintf(stderr, "ERROR: Generate folder \"%s\" failed at %s, line %d. \n", dir_name, __FILE__, __LINE__);
		return KAT_FILE_OPERATE_FAILED;
	}
	file_output = fopen(file_path, "wb");
	if (NULL == file_output)
	{
		fprintf(stderr, "ERROR: Generate \"%s\" failed at %s, line %d. \n", algoname_output, __FILE__, __LINE__);
		return KAT_FILE_OPERATE_FAILED;
	}

	pk_len_bytes = sig_get_pk_len_bytes();
	sk_len_bytes = sig_get_sk_len_bytes();
	sn_len_bytes = sig_get_sn_len_bytes();
	pk = (unsigned char *)calloc(pk_len_bytes, sizeof(unsigned char));
	sk = (unsigned char *)calloc(sk_len_bytes, sizeof(unsigned char));
	sn = (unsigned char *)calloc(sn_len_bytes, sizeof(unsigned char));
	seed = (unsigned char *)calloc(SEED_LEN_BYTES, sizeof(unsigned char));
	m = (unsigned char *)calloc(128, sizeof(unsigned char));
	for (int i = 0; i < 10; i++)
	{
		fprintf(file_output, "Count = %d\n", i);
		// generate seed using drng_seed
		get_random_number(&drng_seed, seed, SEED_LEN_BYTES * 8);
		// generate message using drng_msg
		get_random_number(&drng_msg, m, m_len_bytes * 8);
		// print seed
		fprintf(file_output, "Seed_Len = %d\n", SEED_LEN_BYTES);
		fprintstr(file_output, "Seed = ", seed, SEED_LEN_BYTES);

		/****************the SIG scheme starts here****************/
		// init drng_algorithm using seed
		init_random_number(&drng_algorithm, seed, SEED_LEN_BYTES);

		/****************       Key generate       ****************/
		rtn = sig_keygen(pk, &pk_len_bytes, sk, &sk_len_bytes);
		if (rtn)
		{
			fprintf(stderr, "ERROR: sig_keygen returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_SIG_CRYPTO_FAILURE;
		}
		// print public key
		fprintlen(file_output, "PK_Len = ", pk_len_bytes);
		fprintstr(file_output, "PK = ", pk, pk_len_bytes);
		// print private key
		fprintlen(file_output, "SK_Len = ", sk_len_bytes);
		fprintstr(file_output, "SK = ", sk, sk_len_bytes);
		// print message
		fprintf(file_output, "M_Len = %d\n", m_len_bytes);
		fprintstr(file_output, "M = ", m, m_len_bytes);

		/****************            Sign          ****************/
		rtn = sig_sign(sk, sk_len_bytes, m, m_len_bytes, sn, &sn_len_bytes);
		if (rtn)
		{
			fprintf(stderr, "ERROR: sig_sign returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_SIG_CRYPTO_FAILURE;
		}
		// print signature
		fprintlen(file_output, "Sn_Len = ", sn_len_bytes);
		fprintstr(file_output, "Sn = ", sn, sn_len_bytes);

		/****************           Verify         ****************/
		rtn = sig_verify(pk, pk_len_bytes, sn, sn_len_bytes, m, m_len_bytes);
		if (rtn)
		{
			fprintf(stderr, "ERROR: sig_verify returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_SIG_CRYPTO_FAILURE;
		}
		fprintf(file_output, "\n");
		m_len_bytes += 8;
	}
	free(m);
	free(seed);
	free(sn);
	free(sk);
	free(pk);
	free(nonce2);
	free(nonce1);
	// close KAT_SIG_AlgorithmInstance.txt
	if (0 != fclose(file_output))
	{
		fprintf(stderr, "ERROR: Generate \"%s\" failed at %s, line %d. \n", algoname_output, __FILE__, __LINE__);
		return KAT_FILE_OPERATE_FAILED;
	}
	printf("\nFiles have been saved in the 'output' folder within the working directory.\n");
	return KAT_SIG_SUCCESS;
}

static int validate_algorithm_instance_name(const char *algorithm)
{
	int rt = 0;
	char c = '\0';
	if (strlen(algorithm) > 64)
		rt = KAT_ALGORITHM_INSTANCE_NAME_INVALID;

	for (int i = 0; algorithm[i] != '\0'; i++)
	{
		c = algorithm[i];
		if (!(isalnum(c) || '-' == c || '_' == c))
		{
			rt = KAT_ALGORITHM_INSTANCE_NAME_INVALID;
		}
	}
	return rt;
}

static int create_directory(const char *path)
{
#if defined(_WIN32)
	if (0 == _mkdir(path))
		return 0;
#else
	if (0 == mkdir(path, 0755))
		return 0;
#endif

	if (errno == EEXIST)
	{
#if defined(_WIN32)
		if (0 == _access(path, 0))
			return 0;
#else
		if (0 == access(path, F_OK))
			return 0;
#endif
	}
	return 1;
}

static void fprintlen(FILE *file_output, char *identifier, unsigned long long len)
{
	if (OUTPUT_BLANK_TEST_VECTORS)
		fprintf(file_output, "%s\n", identifier);
	else
		fprintf(file_output, "%s%llu\n", identifier, len);
}

static void fprintstr(FILE *file_output, char *identifier, unsigned char *msg, unsigned long long len)
{
	fprintf(file_output, "%s", identifier);
	for (unsigned long long i = 0; i < len; i++)
		fprintf(file_output, "%02X", msg[i]);
	fprintf(file_output, "\n");
}