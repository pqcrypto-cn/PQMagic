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
#include "KEX_AlgorithmInstance.h"
#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define SEED_LEN_BYTES 64
#define KAT_KEX_SUCCESS 0
#define KAT_ALGORITHM_INSTANCE_NAME_INVALID -1
#define KAT_FILE_OPERATE_FAILED -2
#define KAT_KEX_CRYPTO_FAILURE -3
#define KAT_MEMORY_ALLOCATION_FAILED -4
#define KAT_KEX_PASS_ERROR -5
#define KAT_KEX_SS_UNEQUAL -6

static int validate_algorithm_instance_name(const char *algorithm);
static int create_directory(const char *path);
static void fprintlen(FILE *file_output, char *identifier, unsigned long long len);
static void fprintstr(FILE *file_output, char *identifier, unsigned char *msg, unsigned long long len);

// DRNG_ctx for generating pseudorandom numbers within the KEX protocol
DRNG_ctx drng_algorithm;

/****************output KAT_KEX_AlgorithmInstance.txt****************/
int main()
{
	unsigned char *nonce;
	// DRNG_ctx for generating seed
	DRNG_ctx drng_seed;
	char algoname_output[96];
	FILE *file_output;
	unsigned char *seed, *pka, *ska, *pkb, *skb, *sta, *stb, *ssa, *ssb, *m1, *m2, *m3, *ma, *mb;
	unsigned long long pass, pka_len_bytes, ska_len_bytes, pkb_len_bytes,
		skb_len_bytes, sta_len_bytes, stb_len_bytes, ssa_len_bytes, ssb_len_bytes,
		m1_len_bytes, m2_len_bytes, m3_len_bytes, ma_len_bytes, mb_len_bytes, total_len_bytes;
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
	// open KAT_KEX_AlgorithmInstance.txt
	const char *dir_name = "output";
	char file_path[128] = "";
	sprintf(algoname_output, "KAT_KEX_%s.txt", ALGORITHM_INSTANCE);
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

	pass = kex_get_passes_num();
	pka_len_bytes = kex_get_pk_len_bytes();
	ska_len_bytes = kex_get_sk_len_bytes();
	pkb_len_bytes = kex_get_pk_len_bytes();
	skb_len_bytes = kex_get_sk_len_bytes();
	sta_len_bytes = kex_get_sta_len_bytes();
	stb_len_bytes = kex_get_stb_len_bytes();
	ssa_len_bytes = kex_get_ss_len_bytes();
	ssb_len_bytes = kex_get_ss_len_bytes();
	total_len_bytes = kex_get_total_msg_len_bytes();
	m1_len_bytes = 0;
	m2_len_bytes = 0;
	m3_len_bytes = 0;
	ma_len_bytes = 0;
	mb_len_bytes = 0;
	pka = (unsigned char *)calloc(pka_len_bytes, sizeof(unsigned char));
	ska = (unsigned char *)calloc(ska_len_bytes, sizeof(unsigned char));
	pkb = (unsigned char *)calloc(pkb_len_bytes, sizeof(unsigned char));
	skb = (unsigned char *)calloc(skb_len_bytes, sizeof(unsigned char));
	sta = (unsigned char *)calloc(sta_len_bytes, sizeof(unsigned char));
	stb = (unsigned char *)calloc(stb_len_bytes, sizeof(unsigned char));
	ssa = (unsigned char *)calloc(ssa_len_bytes, sizeof(unsigned char));
	ssb = (unsigned char *)calloc(ssb_len_bytes, sizeof(unsigned char));
	m1 = (unsigned char *)calloc(total_len_bytes, sizeof(unsigned char));
	m2 = (unsigned char *)calloc(total_len_bytes, sizeof(unsigned char));
	m3 = (unsigned char *)calloc(total_len_bytes, sizeof(unsigned char));
	ma = NULL;
	mb = NULL;
	seed = (unsigned char *)calloc(SEED_LEN_BYTES, sizeof(unsigned char));
	for (int i = 0; i < 10; i++)
	{
		fprintf(file_output, "Count = %d\n", i);
		// generate seed using drng_seed
		get_random_number(&drng_seed, seed, SEED_LEN_BYTES * 8);
		// print seed
		fprintf(file_output, "Seed_Len = %d\n", SEED_LEN_BYTES);
		fprintstr(file_output, "Seed = ", seed, SEED_LEN_BYTES);

		/****************the KEX protocol starts here****************/
		// init drng_algorithm using seed
		init_random_number(&drng_algorithm, seed, SEED_LEN_BYTES);

		fprintlen(file_output, "Pass_Num = ", pass);
		/**************** Initialize by the initiator****************/
		rtn = kex_init_a(
			pka, &pka_len_bytes,
			ska, &ska_len_bytes,
			sta, &sta_len_bytes);
		if (rtn < KAT_KEX_SUCCESS)
		{
			fprintf(stderr, "ERROR: kex_init_a returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_KEX_CRYPTO_FAILURE;
		}
		// print initiator long-term public key
		fprintlen(file_output, "PKa_Len = ", pka_len_bytes);
		fprintstr(file_output, "PKa = ", pka, pka_len_bytes);
		// print initiator long-term private key
		fprintlen(file_output, "SKa_Len = ", ska_len_bytes);
		fprintstr(file_output, "SKa = ", ska, ska_len_bytes);
		// print initiator state information
		fprintlen(file_output, "Init_Sta_Len = ", sta_len_bytes);
		fprintstr(file_output, "Init_Sta = ", sta, sta_len_bytes);

		/**************** Initialize by the responder****************/
		rtn = kex_init_b(
			pkb, &pkb_len_bytes,
			skb, &skb_len_bytes,
			stb, &stb_len_bytes);
		if (rtn < KAT_KEX_SUCCESS)
		{
			fprintf(stderr, "ERROR: kex_init_b returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_KEX_CRYPTO_FAILURE;
		}
		// print responder long-term public key
		fprintlen(file_output, "PKb_Len = ", pkb_len_bytes);
		fprintstr(file_output, "PKb = ", pkb, pkb_len_bytes);
		// print responder long-term private key
		fprintlen(file_output, "SKb_Len = ", skb_len_bytes);
		fprintstr(file_output, "SKb = ", skb, skb_len_bytes);
		// print responder state information
		fprintlen(file_output, "Init_Stb_Len = ", stb_len_bytes);
		fprintstr(file_output, "Init_Stb = ", stb, stb_len_bytes);

		for (;;)
		{
			/***   Generate the first-pass message sent by the initiator  ***/
			rtn = kex_generate_pass1_msg_a(
				ska, ska_len_bytes,
				pkb, pkb_len_bytes,
				sta, &sta_len_bytes,
				m1, &m1_len_bytes);
			if (rtn < KAT_KEX_SUCCESS)
			{
				fprintf(stderr, "ERROR: kex_generate_pass1_msg_a returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
				return KAT_KEX_CRYPTO_FAILURE;
			}
			// print initiator state information
			fprintlen(file_output, "Pass1_Sta_Len = ", sta_len_bytes);
			fprintstr(file_output, "Pass1_Sta = ", sta, sta_len_bytes);
			// print message sent by initiator
			fprintlen(file_output, "M1_Len = ", m1_len_bytes);
			fprintstr(file_output, "M1 = ", m1, m1_len_bytes);
			ma = m1;
			ma_len_bytes = m1_len_bytes;
			if (rtn == 1)
			{
				if (pass != 1)
				{
					fprintf(stderr, "ERROR: kex_generate_pass1_msg_a returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
					return KAT_KEX_PASS_ERROR;
				}
				break;
			}

			/***   generate the second-pass message sent by the responder  ***/
			rtn = kex_generate_pass2_msg_b(
				skb, skb_len_bytes,
				pka, pka_len_bytes,
				m1, m1_len_bytes,
				stb, &stb_len_bytes,
				m2, &m2_len_bytes);
			if (rtn < KAT_KEX_SUCCESS)
			{
				fprintf(stderr, "ERROR: kex_generate_pass2_msg_b returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
				return KAT_KEX_CRYPTO_FAILURE;
			}
			// print responder state information
			fprintlen(file_output, "Pass2_Stb_Len = ", stb_len_bytes);
			fprintstr(file_output, "Pass2_Stb = ", stb, stb_len_bytes);
			// print message sent by responder
			fprintlen(file_output, "M2_Len = ", m2_len_bytes);
			fprintstr(file_output, "M2 = ", m2, m2_len_bytes);
			mb = m2;
			mb_len_bytes = m2_len_bytes;
			if (rtn == 1)
			{
				if (pass != 2)
				{
					fprintf(stderr, "ERROR: kex_generate_pass2_msg_b returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
					return KAT_KEX_PASS_ERROR;
				}
				break;
			}

			/***** generate the third-pass message sent by the initiator *****/
			rtn = kex_generate_pass3_msg_a(
				ska, ska_len_bytes,
				pkb, pkb_len_bytes,
				m2, m2_len_bytes,
				sta, &sta_len_bytes,
				m3, &m3_len_bytes);
			if (rtn < KAT_KEX_SUCCESS)
			{
				fprintf(stderr, "ERROR: kex_generate_pass3_msg_a returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
				return KAT_KEX_CRYPTO_FAILURE;
			}
			// print initiator state information
			fprintlen(file_output, "Pass3_Sta_Len = ", sta_len_bytes);
			fprintstr(file_output, "Pass3_Sta = ", sta, sta_len_bytes);
			// print message sent by initiator
			fprintlen(file_output, "M3_Len = ", m3_len_bytes);
			fprintstr(file_output, "M3 = ", m3, m3_len_bytes);
			ma = m3;
			ma_len_bytes = m3_len_bytes;
			if (rtn == 1)
			{
				if (pass != 3)
				{
					fprintf(stderr, "ERROR: kex_generate_pass3_msg_a returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
					return KAT_KEX_PASS_ERROR;
				}
				break;
			}

			/*
			For key exchange protocols with more passes, implement the  
			program likewise:
				rtn = kex_generate_pass4_msg_b(
					skb, skb_len_bytes,
					pka, pka_len_bytes,
					m3, m3_len_bytes,
					stb, &stb_len_bytes,
					m4, &m4_len_bytes);
				...
				rtn = kex_generate_pass5_msg_a(
					ska, ska_len_bytes,
					pkb, pkb_len_bytes,
					m4, m4_len_bytes,
					sta, &sta_len_bytes,
					m5, &m5_len_bytes);
				...
			*/
			break;
		}

		rtn = kex_derive_ss_a(
			ska, ska_len_bytes,
			pkb, pkb_len_bytes,
			mb, mb_len_bytes,
			sta, sta_len_bytes,
			ssa, &ssa_len_bytes);
		if (rtn < KAT_KEX_SUCCESS)
		{
			fprintf(stderr, "ERROR: kex_derive_ss_a returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_KEX_CRYPTO_FAILURE;
		}

		rtn = kex_derive_ss_b(
			skb, skb_len_bytes,
			pka, pka_len_bytes,
			ma, ma_len_bytes,
			stb, stb_len_bytes,
			ssb, &ssb_len_bytes);
		if (rtn < KAT_KEX_SUCCESS)
		{
			fprintf(stderr, "ERROR: kex_derive_ss_b returned %d at %s, line %d. \n", rtn, __FILE__, __LINE__);
			return KAT_KEX_CRYPTO_FAILURE;
		}

		// verify two shared secret keys
		if (ssa_len_bytes != ssb_len_bytes || memcmp(ssa, ssb, ssa_len_bytes))
		{
			fprintf(stderr, "ERROR: initiator shared secret key != responder shared secret key at %s, line %d. \n", __FILE__, __LINE__);
			return KAT_KEX_SS_UNEQUAL;
		}
		// print shared secret key
		fprintlen(file_output, "SS_Len = ", ssa_len_bytes);
		fprintstr(file_output, "SS = ", ssa, ssa_len_bytes);
		fprintf(file_output, "\n");
	}
	free(seed);
	free(m1);
	free(m2);
	free(m3);
	free(ssa);
	free(ssb);
	free(stb);
	free(sta);
	free(skb);
	free(pkb);
	free(ska);
	free(pka);
	free(nonce);
	// close KAT_KEX_AlgorithmInstance.txt
	if (0 != fclose(file_output))
	{
		fprintf(stderr, "ERROR: Generate \"%s\" failed at %s, line %d. \n", algoname_output, __FILE__, __LINE__);
		return KAT_FILE_OPERATE_FAILED;
	}
	printf("\nFiles have been saved in the 'output' folder within the working directory.\n");
	return KAT_KEX_SUCCESS;
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