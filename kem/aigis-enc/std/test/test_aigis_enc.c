
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "api.h"
#include "utils/randombytes.h"

#define	NTESTS		     1000
#define SUCCESS          0
#define CRYPTO_FAILURE  -1

int     random_ml_kem_test(void);


int 
random_ml_kem_test(void) {
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    for(int i = 0; i < NTESTS; ++i) {

        // Generate the public/private keypair
        if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return CRYPTO_FAILURE;
        }

        if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
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
    }

    return SUCCESS;
}

int
main(void)
{
    int ret = random_ml_kem_test();

    if(ret == SUCCESS) {
        printf("[+] Success.\n");
        printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
        printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
        printf("CRYPTO_CIPHERTEXTBYTES = %d\n", CRYPTO_CIPHERTEXTBYTES);
        printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);
    } else {
        printf("[-] Error.\n");
    }
    
    return 0;
}


