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
#include "KEM_AlgorithmInstance.h"
#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define SEED_LEN_BYTES 64
#define KAT_KEM_SUCCESS 0
#define KAT_ALGORITHM_INSTANCE_NAME_INVALID -1
#define KAT_FILE_OPERATE_FAILED -2
#define KAT_KEM_CRYPTO_FAILURE -3
#define KAT_MEMORY_ALLOCATION_FAILED -4
#define KAT_KEM_SS_UNEQUAL -5

static int validate_algorithm_instance_name(const char *algorithm);
static int create_directory(const char *path);
static void fprintlen(FILE *file_output, char *identifier, unsigned long long len);
static void fprintstr(FILE *file_output, char *identifier, unsigned char *msg, unsigned long long len);

// DRNG_ctx for generating pseudorandom numbers within the KEM scheme
DRNG_ctx drng_algorithm;

/****************output KAT_KEM_AlgorithmInstance.txt****************/
int main()
{
	unsigned char *nonce;
	// DRNG_ctx for generating seed
	DRNG_ctx drng_seed;
	char algoname_output[96];
	FILE *file_output;
	unsigned char *seed, *ss, *ss1, *ct, *pk, *sk;
	unsigned long long pk_len_bytes, sk_len_bytes, ss_len_bytes, ct_len_bytes;
	int rtn;
	if (validate_algorithm_instance_name(ALGORITHM_INSTANCE))
	{
		fprintf(stderr, "ERROR: Invalid algorithm instance name. Only letters, numbers, '-' or '_' are permitted.\n");
		return KAT_ALGORITHM_INSTANCE_NAME_INVALID;
	}
	// init drng_seed using nonce
	nonce = (unsigned char *)calloc(SEED_LEN_BYTES, sizeof(unsigned char));
	for (int i = 0; i < SEED_LEN_BYTES / 4; i++)
	{
		memcpy(nonce + 4 * i, "seed", 4);
	}
	init_random_number(&drng_seed, nonce, SEED_LEN_BYTES);
	// open KAT_KEM_AlgorithmInstance.txt
	const char *dir_name = "output";
	char file_path[128] = "";
	sprintf(algoname_output, "KAT_KEM_%s.txt", ALGORITHM_INSTANCE);
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

	pk_len_bytes = kem_get_pk_len_bytes();
	sk_len_bytes = kem_get_sk_len_bytes();
	ss_len_bytes = kem_get_ss_len_bytes();
	ct_len_bytes = kem_get_ct_len_bytes();
	pk = (unsigned char *)calloc(pk_len_bytes, sizeof(unsigned char));
	sk = (unsigned char *)calloc(sk_len_bytes, sizeof(unsigned char));
	ss = (unsigned char *)calloc(ss_len_bytes, sizeof(unsigned char));
	ss1 = (unsigned char *)calloc(ss_len_bytes, sizeof(unsigned char));
	ct = (unsigned char *)calloc(ct_len_bytes, sizeof(unsigned char));
	seed = (unsigned char *)calloc(SEED_LEN_BYTES, sizeof(unsigned char));
	for (int i = 0; i < 10; i++)
	{
		fprintf(file_output, "Count = %d\n", i);
		// generate seed using drng_seed
		get_random_number(&drng_seed, seed, SEED_LEN_BYTES * 8);
		// print seed
		fprintf(file_output, "Seed_Len = %d\n", SEED_LEN_BYTES);
		fprintstr(file_output, "Seed = ", seed, SEED_LEN_BYTES);

		/****************the KEM scheme starts here****************/
		// init drng_algorithm using seed
		init_random_number(&drng_algorithm, seed, SEED_LEN_BYTES);

		/****************       Key generate       ****************/
		rtn = kem_keygen(pk, &pk_len_bytes, sk, &sk_len_bytes);
		if (rtn)
		{
			fprintf(stderr, "ERROR: kem_keygen returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_KEM_CRYPTO_FAILURE;
		}
		// print public key
		fprintlen(file_output, "PK_Len = ", pk_len_bytes);
		fprintstr(file_output, "PK = ", pk, pk_len_bytes);
		// print private key
		fprintlen(file_output, "SK_Len = ", sk_len_bytes);
		fprintstr(file_output, "SK = ", sk, sk_len_bytes);
		/****************        Encapsulate       ****************/
		rtn = kem_enc(pk, pk_len_bytes, ss, &ss_len_bytes, ct, &ct_len_bytes);
		if (rtn)
		{
			fprintf(stderr, "ERROR: kem_enc returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_KEM_CRYPTO_FAILURE;
		}
		// print ciphertext
		fprintlen(file_output, "CT_Len = ", ct_len_bytes);
		fprintstr(file_output, "CT = ", ct, ct_len_bytes);
		// print encapsulation shared secret key
		fprintlen(file_output, "SS_Len = ", ss_len_bytes);
		fprintstr(file_output, "SS = ", ss, ss_len_bytes);

		/****************        Decapsulate       ****************/
		rtn = kem_dec(sk, sk_len_bytes, ct, ct_len_bytes, ss1, &ss_len_bytes);
		if (rtn)
		{
			fprintf(stderr, "ERROR: kem_dec returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_KEM_CRYPTO_FAILURE;
		}
		// verify decapsulation result
		if (memcmp(ss, ss1, ss_len_bytes))
		{
			fprintf(stderr, "ERROR: decapsulation shared secret key != encapsulation shared secret key at %s, line %d. \n", __FILE__, __LINE__);
			return KAT_KEM_SS_UNEQUAL;
		}
		fprintf(file_output, "\n");
	}
	free(seed);
	free(ct);
	free(ss1);
	free(ss);
	free(sk);
	free(pk);
	free(nonce);
	// close KAT_KEM_AlgorithmInstance.txt
	if (0 != fclose(file_output))
	{
		fprintf(stderr, "ERROR: Generate \"%s\" failed at %s, line %d. \n", algoname_output, __FILE__, __LINE__);
		return KAT_FILE_OPERATE_FAILED;
	}
	printf("\nFiles have been saved in the 'output' folder within the working directory.\n");
	return KAT_KEM_SUCCESS;
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