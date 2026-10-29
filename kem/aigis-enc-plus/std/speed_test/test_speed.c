#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../api.h"
#include "../randombytes.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 10000

uint64_t t[NTESTS];

int main()
{
  unsigned int i;
  unsigned char pk[CRYPTO_PUBLICKEYBYTES + 32] = {0};
  unsigned char sk[CRYPTO_SECRETKEYBYTES + 32] = {0};
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES +32] = {0};
  __attribute__((aligned(32)))
  unsigned char key[CRYPTO_BYTES] = {0};
  unsigned char       entropy_input[48];

for (int i=0; i<48; i++)
        entropy_input[i] = i;

  //  randombytes_init(entropy_input, NULL, 256);

  
  
  printf("*****************************\n");
  printf("PK Sizes:%d\n",CRYPTO_PUBLICKEYBYTES);
  printf("SK Sizes:%d\n",CRYPTO_SECRETKEYBYTES);
  printf("CT Sizes:%d\n",CRYPTO_CIPHERTEXTBYTES);
  printf("TOTAL COST:%d\n",CRYPTO_CIPHERTEXTBYTES + CRYPTO_PUBLICKEYBYTES);
  printf("*****************************\n");
  
  
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    mkem_keygen(pk, sk);
  }
  print_results("Aigis-enc_keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    mkem_enc(pk,key,ct);
  }
  print_results("Aigis-enc_encaps: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    if(mkem_dec(sk, ct, key))
	printf("decryption failure!\n");
  }
  print_results("Aigis-enc_decaps: ", t, NTESTS);

  return 0;
}
