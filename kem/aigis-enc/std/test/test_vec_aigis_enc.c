#include <string.h>
#include <ctype.h>
#include "../api.h"
#include "utils/randombytes.h"

#define	NTESTS		     10
#define	MAX_MARKER_LEN   50
#define SUCCESS          0
#define CRYPTO_FAILURE  -1

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);
int     gen_aigis_enc_test_vec(void);
int     check_aigis_enc_use_test_vec(void);


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

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L) {
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

int gen_aigis_enc_test_vec(void) {
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    unsigned char keypair_coins[2*SEED_BYTES];
    unsigned char kem_enc_coins[SEED_BYTES];

    char filename[32] = {0};
    sprintf(filename, "./aigis_enc_%d_test_vectors.txt", AIGIS_ENC_MODE);
    printf("Gen test vector file: %s\n", filename);
    FILE *fp = fopen(filename, "a");

    fprintf(fp, "NUM = %d\n\n", NTESTS);

    for(int i = 0; i < NTESTS; ++i) {

        randombytes(keypair_coins, 2*SEED_BYTES);
        randombytes(kem_enc_coins, SEED_BYTES);
        // Generate the public/private keypair
        if ( (ret_val = crypto_kem_keypair_internal(pk, sk, keypair_coins)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return CRYPTO_FAILURE;
        }

        if ( (ret_val = crypto_kem_enc_internal(ct, ss, pk, kem_enc_coins)) != 0) {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return CRYPTO_FAILURE;
        }

        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return CRYPTO_FAILURE;
        }

        if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
            printf("crypto_kem_dec returned bad 'ss' value\n");
            return CRYPTO_FAILURE;
        }

        fprintf(fp, "TEST VEC %d\n", i);
        fprintBstr(fp, "keypair coins = ", keypair_coins, 2*SEED_BYTES);
        fprintBstr(fp, "kem_enc coins = ", kem_enc_coins, SEED_BYTES);
        fprintBstr(fp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);
        fprintBstr(fp, "ct = ", ct, CRYPTO_CIPHERTEXTBYTES);
        fprintBstr(fp, "ss = ", ss, CRYPTO_BYTES);
        fprintf(fp, "\n");
    }

    fclose(fp);
    printf("Finish.\n");

    return SUCCESS;
}

int check_aigis_enc_use_test_vec(void) {

    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char       ct_ground_truth[CRYPTO_CIPHERTEXTBYTES], ss_ground_truth[CRYPTO_BYTES];
    unsigned char       pk_ground_truth[CRYPTO_PUBLICKEYBYTES], sk_ground_truth[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    unsigned char keypair_coins[2*SEED_BYTES];
    unsigned char kem_enc_coins[SEED_BYTES];

    char filename[32] = {0};
    sprintf(filename, "./aigis_enc_%d_test_vectors.txt", AIGIS_ENC_MODE);
    printf("Check aigis_enc_%d using test vector file: %s\n", AIGIS_ENC_MODE, filename);
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

        if ( !ReadHex(fp, keypair_coins, 2*SEED_BYTES, "keypair coins = ") ){
            printf("\n\t[-] Read keypair coins error! Make sure TEST VEC file is correct.\n");
            continue;
        }
        if ( !ReadHex(fp, kem_enc_coins, SEED_BYTES, "kem_enc coins = ") ){
            printf("\n\t[-] Read kem_enc coins error! Make sure TEST VEC file is correct.\n");
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
        if ( !ReadHex(fp, ct_ground_truth, CRYPTO_CIPHERTEXTBYTES, "ct = ") ){
            printf("\n\t[-] Read ct error! Make sure TEST VEC file is correct.\n");
            continue;
        }
        if ( !ReadHex(fp, ss_ground_truth, CRYPTO_BYTES, "ss = ") ){
            printf("\n\t[-] Read ss error! Make sure TEST VEC file is correct.\n");
            continue;
        }

        // Generate the public/private keypair
        if ( (ret_val = crypto_kem_keypair_internal(pk, sk, keypair_coins)) != 0) {
            printf("\n\t[-] FAILED! crypto_kem_keypair returned <%d>\n", ret_val);
            failed = 1;
            continue;
        }

        // Check if pk/sk generated correctly.
        if ( memcmp(pk, pk_ground_truth, CRYPTO_PUBLICKEYBYTES) ) {
            printf("\n\t[-] FAILED! Generated pk error.\n");
            failed = 1;
            continue;
        }
        if ( memcmp(sk, sk_ground_truth, CRYPTO_SECRETKEYBYTES) ) {
            printf("\n\t[-] FAILED! Generated sk error.\n");
            failed = 1;
            continue;
        }
        
        // Generate ct and ss.
        if ( (ret_val = crypto_kem_enc_internal(ct, ss, pk_ground_truth, kem_enc_coins)) != 0) {
            printf("\n\t[-] FAILED! crypto_kem_enc returned <%d>\n", ret_val);
            failed = 1;
            continue;
        }

        // Check if ct/ss generated correctly.
        if ( memcmp(ct, ct_ground_truth, CRYPTO_CIPHERTEXTBYTES) ) {
            printf("\n\t[-] FAILED! Generated ct error.\n");
            failed = 1;
            continue;
        }
        if ( memcmp(ss, ss_ground_truth, CRYPTO_BYTES) ) {
            printf("\n\t[-] FAILED! Generated ss error.\n");
            failed = 1;
            continue;
        }


        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            printf("\n\t[-] FAILED! crypto_kem_dec returned <%d>\n", ret_val);
            failed = 1;
            continue;
        }

        if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
            printf("\n\t[-] FAILED! crypto_kem_dec returned bad 'ss' value\n");
            failed = 1;
            continue;
        }

        printf(" SUCCESS!\n");

    } while ( !done );

    fclose(fp);

    if ( failed ) {
        return CRYPTO_FAILURE;
    }

    return SUCCESS;
}

int main() {
    // gen_aigis_enc_test_vec();
    check_aigis_enc_use_test_vec();
}