#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../sign.h"
#include "utils/randombytes.h"

#define	NTESTS		     10
#define	MAX_MARKER_LEN   50
#define MLEN             59
#define SUCCESS          0
#define CRYPTO_FAILURE  -1

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long LL);
int     gen_dilithium_test_vec(void);
int     check_dilithium_use_test_vec(void);
#define crypto_sign_verify_internal crypto_sign_verify


//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	int		i, len;
	int curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
		len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = curr_line;
		if (curr_line == EOF )
		    return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
	int			i, ch, started;
	unsigned char	ich;

	if ( Length == 0 ) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = ch - '0';
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = ch - 'A' + 10;
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;

			for ( i=0; i<Length-1; i++ )
				A[i] = (A[i] << 4) | (A[i+1] >> 4);
			A[Length-1] = (A[Length-1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long LL) {
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<LL; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( LL == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

int gen_dilithium_test_vec(void) {
    unsigned char       ctx[5], m[MLEN], mext[MLEN + 5 + 2], sig[CRYPTO_BYTES];
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    // int                 ret_val;
    unsigned char       ctx_len = 5;
    size_t siglen;

    unsigned char keypair_coins[SEEDBYTES];
    unsigned char sign_coins[CRHBYTES];

    char filename[32] = {0};
    sprintf(filename, "./dilithium_%d_test_vectors.txt", DILITHIUM_MODE);
    printf("Gen test vector file: %s\n", filename);
    FILE *fp = fopen(filename, "a");

    fprintf(fp, "NUM = %d\n\n", NTESTS);

    for(int i = 0; i < NTESTS; ++i) {

        randombytes(keypair_coins, SEEDBYTES);
        randombytes(sign_coins, CRHBYTES);
        randombytes(ctx, ctx_len);
        randombytes(m, MLEN);
        mext[0] = 0;
        mext[1] = (uint8_t)ctx_len;
        memcpy(mext + 2, ctx, ctx_len);
        memcpy(mext + 2 + ctx_len, m, MLEN);

        // Generate the public/private keypair
        crypto_sign_keypair_internal(pk, sk, keypair_coins);

        crypto_sign_signature_internal(sig, &siglen, mext, MLEN + 5 + 2, sign_coins, sk);

        if ( crypto_sign_verify_internal(sig, siglen, mext, MLEN + 5 + 2, pk) ) {
            printf("crypto_dsa_dec error.\n");
            return CRYPTO_FAILURE;
        }

        fprintf(fp, "TEST VEC %d\n", i);
        fprintBstr(fp, "keypair coins = ", keypair_coins, SEEDBYTES);
        fprintBstr(fp, "sign coins = ", sign_coins, CRHBYTES);
        fprintBstr(fp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);
		fprintf(fp, "ctx_len = %hhd\n", ctx_len);
        fprintBstr(fp, "ctx = ", ctx , ctx_len);
        fprintf(fp, "mlen = %d\n", MLEN);
        fprintBstr(fp, "m = ", m, MLEN);
        fprintBstr(fp, "sig = ", sig, siglen);
        fprintf(fp, "\n");
    }

    fclose(fp);
    printf("Finish.\n");

    return SUCCESS;
}

int check_dilithium_use_test_vec(void) {

    unsigned char       ctx[5], m[MLEN], *mext, sig[CRYPTO_BYTES], sig_ground_truth[CRYPTO_BYTES];
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char       pk_ground_truth[CRYPTO_PUBLICKEYBYTES], sk_ground_truth[CRYPTO_SECRETKEYBYTES];
    unsigned char       ctx_len;
	int mlen;
    size_t siglen;
	int ret_val;

    unsigned char keypair_coins[SEEDBYTES];
    unsigned char sign_coins[CRHBYTES];

    char filename[32] = {0};
    sprintf(filename, "./dilithium_%d_test_vectors.txt", DILITHIUM_MODE);
    printf("Check dilithium_%d using test vector file: %s\n", DILITHIUM_MODE, filename);
    FILE *fp = fopen(filename, "r");

    int done = 0;
    int count = 0;
    int failed = 0;
    do {
        if ( FindMarker(fp, "TEST VEC ") )
            fscanf(fp, "%d", &count);
        else {
            done = 1;
            break;
        }

        printf("[+] Check TEST VEC %d ...", count);

        if ( !ReadHex(fp, keypair_coins, SEEDBYTES, "keypair coins = ") ){
            printf("\n\t[-] Read keypair coins error! Make sure TEST VEC file is correct.\n");
            continue;
        }
        if ( !ReadHex(fp, sign_coins, CRHBYTES, "sign coins = ") ){
            printf("\n\t[-] Read sign coins error! Make sure TEST VEC file is correct.\n");
            continue;
        }
        if ( !ReadHex(fp, pk_ground_truth, CRYPTO_PUBLICKEYBYTES, "pk = ") ){
            printf("\n\t[-] Read pk error! Make sure TEST VEC file is correct.\n");
            continue;
        }
        if ( !ReadHex(fp, sk_ground_truth, CRYPTO_SECRETKEYBYTES, "sk = ") ){
            printf("\n\t[-] Read sk error! Make sure TEST VEC file is correct.\n");
            continue;
        }
		if ( FindMarker(fp, "ctx_len = ") )
            fscanf(fp, "%hhu", &ctx_len);
        else {
            printf("\n\t[-] Read ctx_len error! Make sure TEST VEC file is correct.\n");
        }
        if ( !ReadHex(fp, ctx, ctx_len, "ctx = ") ){
            printf("\n\t[-] Read ct error! Make sure TEST VEC file is correct.\n");
            continue;
        }
		if ( FindMarker(fp, "mlen = ") )
            fscanf(fp, "%d", &mlen);
        else {
            printf("\n\t[-] Read mlen error! Make sure TEST VEC file is correct.\n");
        }
        if ( !ReadHex(fp, m, mlen, "m = ") ){
            printf("\n\t[-] Read m error! Make sure TEST VEC file is correct.\n");
            continue;
        }
		if ( !ReadHex(fp, sig_ground_truth, CRYPTO_BYTES, "sig = ") ){
            printf("\n\t[-] Read sig error! Make sure TEST VEC file is correct.\n");
            continue;
        }

		mext = (unsigned char*)malloc(ctx_len + mlen + 2);
		mext[0] = 0;
        mext[1] = (uint8_t)ctx_len;
        memcpy(mext + 2, ctx, ctx_len);
        memcpy(mext + 2 + ctx_len, m, mlen);

        // Generate the public/private keypair
        if ( (ret_val = crypto_sign_keypair_internal(pk, sk, keypair_coins)) != 0) {
            printf("\n\t[-] FAILED! crypto_dsa_keypair returned <%d>\n", ret_val);
            failed = 1;
			free(mext);
            continue;
        }

        // Check if pk/sk generated correctly.
        if ( memcmp(pk, pk_ground_truth, CRYPTO_PUBLICKEYBYTES) ) {
            printf("\n\t[-] FAILED! Generated pk error.\n");
            failed = 1;
			free(mext);
            continue;
        }
        if ( memcmp(sk, sk_ground_truth, CRYPTO_SECRETKEYBYTES) ) {
            printf("\n\t[-] FAILED! Generated sk error.\n");
            failed = 1;
			free(mext);
            continue;
        }

        // Generate sig.
        if ( (ret_val = crypto_sign_signature_internal(sig, &siglen, mext, mlen + ctx_len + 2, sign_coins, sk)) != 0) {
            printf("\n\t[-] FAILED! crypto_dsa_enc returned <%d>\n", ret_val);
            failed = 1;
			free(mext);
            continue;
        }

        // Check if sig generated correctly.
        if ( memcmp(sig, sig_ground_truth, CRYPTO_BYTES) || siglen != CRYPTO_BYTES ) {
            printf("\n\t[-] FAILED! Generated sig error.\n");
            failed = 1;
            free(mext);
			continue;
        }


        if ( (ret_val = crypto_sign_verify_internal(sig, siglen, mext, mlen + ctx_len + 2, pk)) != 0) {
            printf("\n\t[-] FAILED! crypto_dsa_dec returned <%d>\n", ret_val);
            failed = 1;
            free(mext);
			continue;
        }

		free(mext);

        printf(" SUCCESS!\n");

    } while ( !done );

    fclose(fp);

    if ( failed ) {
        return CRYPTO_FAILURE;
    }

    return SUCCESS;
}

int main() {
    // gen_dilithium_test_vec();
    check_dilithium_use_test_vec();
}