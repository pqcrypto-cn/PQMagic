#include <stdio.h>
#include "api.h"
#include "randombytes.h"
#include "speed.h"
#include "cpucycles.h"
#include "polyvec.h"
#include "pspm.h"

#define MLEN 59

#define NTESTS 30000



int main(void)
{
  // srand(0);

  unsigned int i;
  int ret;
  unsigned long long mlen = MLEN, smlen;
  unsigned char m[64];
  unsigned char sm[SIG_BYTES];
  unsigned char pk[SIG_PUBLICKEYBYTES];
  unsigned char sk[SIG_SECRETKEYBYTES];
  unsigned long long t0[NTESTS], t1[NTESTS], t2[NTESTS];

  printf("\n**********************************\n");
  printf("PK Sizes : %d\n", SIG_PUBLICKEYBYTES);
  printf("SK Sizes : %d\n", SIG_SECRETKEYBYTES);
  printf("SIG Sizes: %d\n", SIG_BYTES);
  printf("Comm. Sizes: %d\n", SIG_PUBLICKEYBYTES + SIG_BYTES);
  printf("**********************************\n\n");

  // int64_t zzzz= (int64_t)((1LL << (21 + 32)) + PARAM_Q/2)/PARAM_Q;
  // printf("\nv: %lld\n\n", zzzz);


  msig_keygen(pk, sk);
  msig_sign(sk, m, mlen, sm, &smlen);
  msig_verf(pk, sm, smlen, m, mlen);



  int count = 0;

  for (i = 0; i < NTESTS; ++i)
  {
    randombytes(m, MLEN);

    t0[i] = cpucycles();
    msig_keygen(pk, sk);
    t0[i] = cpucycles() - t0[i];

    t1[i] = cpucycles();
    count += msig_sign(sk, m, mlen, sm, &smlen);
    t1[i] = cpucycles() - t1[i];

    t2[i] = cpucycles();
    ret = msig_verf(pk, sm, smlen, m, mlen);
    t2[i] = cpucycles() - t2[i];

    if (ret != 0)
    {
      printf("Verification failed %d\n", i);
      break;
    }
    // printf("#(N):%d\n", i);
  }

  print_results("keygen:", t0, NTESTS);
  print_results("sign: ", t1, NTESTS);
  print_results("verify: ", t2, NTESTS);

  return 0;
}


