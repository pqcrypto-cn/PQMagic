#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "api.h"
#include "utils/cpucycles.h"
#include "utils/speed_print.h"

#define NTESTS 10000

void all_cycle_bench(void);
void core_alg_cycle_bench(void);
void kem_enc_dec_bench(double bench_time);
void bench_sm3_extended(double bench_time);
void bench_sm3(double bench_time);


uint64_t t[NTESTS];

void core_alg_cycle_bench(void) {
  unsigned int i;
  unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
  unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
  unsigned char key[CRYPTO_BYTES] = {0};

  printf("============ Start doing Aigis-enc-%d keypair/sign/verify cycle bench ==========\n", PARAMS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_keypair(pk, sk);
  }
  print_results("Aigis-enc keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_enc(ct, key, pk);
  }
  print_results("Aigis-enc encaps: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_dec(key, ct, sk);
  }
  print_results("Aigis-enc decaps: ", t, NTESTS);

  printf("=============================== Finish ============================\n\n");
}

void kem_enc_dec_bench(double bench_time) {
  clock_t clk1, clk2;
  uint64_t i, e;
  double n;
  unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
  unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
  unsigned char key[CRYPTO_BYTES] = {0};


  // crypto_kem_keypair(pk, sk);

  printf("============== Start doing Aigis-enc-%d keypair/sign/verify bench ==============\n", PARAMS);

  n = 0;
  e = 16;
  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_kem_keypair(pk, sk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);
  printf("Aigis-enc keypair %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("Aigis-enc keypair speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  puts("");

  n = 0;
  e = 16;
  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_kem_enc(ct, key, pk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);
  printf("Aigis-enc encaps %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("Aigis-enc encaps speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  puts("");



  n = 0;
  e = 16;
  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_kem_dec(key, ct, sk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);
  printf("Aigis-enc decaps %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("Aigis-enc decaps speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  puts("");

  printf("=============================== Finish ============================\n\n");
}


int main(void)
{

  core_alg_cycle_bench();
  double bench_time = 3.0;
  kem_enc_dec_bench(bench_time);

  return 0;
}
