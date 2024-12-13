#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
// #include "sign.h"
#include "api.h"
#include "utils/randombytes.h"

#define MLEN 59
#define NTESTS 1000
// #define SHOW_MSG

void single_msg_correctness(void);
void multi_random_msg_correctness(void);
void cross_version_verify_corectness(void);

void multi_random_msg_correctness(void) {
  unsigned int i, j;
  int ret;
  size_t mlen, smlen;
  uint8_t m[MLEN] = {0};
  uint8_t sm[MLEN + CRYPTO_BYTES];
  uint8_t m2[MLEN + CRYPTO_BYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  uint8_t ctx[MLEN];
  randombytes(ctx, MLEN);

  printf("================= Start ML-DSA-%d sign/verify test =================\n", ML_DSA_MODE);

  for(i = 0; i < NTESTS; ++i) {
    randombytes(m, MLEN);

    crypto_sign_keypair(pk, sk);
#ifdef SHOW_MSG
    if(i == NTESTS/2 + 198) {
      puts("pk:");
      for(int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        printf("0x%x, ", pk[i]);
      }
      printf("\n");
      puts("sk:");
      for(int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        printf("0x%x, ", sk[i]);
      }
      printf("\n");
    }
#endif

    crypto_sign(sm, &smlen, m, MLEN, ctx, MLEN, sk);
#ifdef SHOW_MSG
    if(i == NTESTS/2 + 198) {
      puts("m:");
      for(int i = 0; i < MLEN; i++) {
        printf("0x%x, ", m[i]);
      }
      printf("\n");
      puts("sm:");
      for(int i = 0; i < MLEN + CRYPTO_BYTES; i++) {
        printf("0x%x, ", sm[i]);
      }
      printf("\n");
    }
#endif

    ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, MLEN, pk);
#ifdef SHOW_MSG
    if(i == NTESTS/2 + 198) {
      puts("m2:");
      for(int i = 0; i < mlen; i++) {
        printf("0x%x, ", m2[i]);
      }
      printf("\n");
    }
#endif

    if(ret) {
      fprintf(stderr, "[-] Verification failed\n");
      return;
    }

    if(mlen != MLEN) {
      fprintf(stderr, "[-] Message lengths don't match\n");
      return;
    }

    for(j = 0; j < mlen; ++j) {
      if(m[j] != m2[j]) {
        fprintf(stderr, "[-] Messages don't match\n");
        return;
      }
    }

    randombytes((uint8_t *)&j, sizeof(j));
    do {
      randombytes(m2, 1);
    } while(!m2[0]);
    sm[j % CRYPTO_BYTES] += m2[0];
    ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, MLEN, pk);
    if(!ret) {
      fprintf(stderr, "[-] Trivial forgeries possible\n");
      return;
    }
  }

  printf("[+] Test success.\n");

  printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);
  printf("================= Finish ML-DSA-%d sign/verify test ================\n", ML_DSA_MODE);
}

int main(void)
{

  multi_random_msg_correctness();
  // single_msg_correctness();
  // cross_version_verify_corectness();

  return 0;
}
