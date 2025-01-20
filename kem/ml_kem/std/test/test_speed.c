#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "api.h"
#include "utils/cpucycles.h"
#include "utils/speed_print.h"

#define NTESTS 10000

void core_alg_cycle_bench(void);
void kem_enc_dec_bench(double bench_time);

uint64_t t[NTESTS];

/*
uint8_t seed[ML_KEM_SYMBYTES] = {0};
void all_cycle_bench(void);
void all_cycle_bench(void) {
  unsigned int i;
  unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
  unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
  unsigned char key[CRYPTO_BYTES] = {0};
  polyvec matrix[ML_KEM_K];
  poly ap;

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    gen_matrix(matrix, seed, 0);
  }
  print_results("gen_a: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_getnoise_eta1(&ap, seed, 0);
  }
  print_results("poly_getnoise_eta1: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_getnoise_eta2(&ap, seed, 0);
  }
  print_results("poly_getnoise_eta2: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_ntt(&ap);
  }
  print_results("NTT: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_invntt_tomont(&ap);
  }
  print_results("INVNTT: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_keypair(pk, sk);
  }
  print_results("ML-KEM keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_enc(ct, key, pk);
  }
  print_results("ML-KEM encaps: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_dec(key, ct, sk);
  }
  print_results("ML-KEM decaps: ", t, NTESTS);
}
*/

void core_alg_cycle_bench(void) {
  unsigned int i;
  unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
  unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
  unsigned char key[CRYPTO_BYTES] = {0};

  printf("============ Start doing ML-KEM-%d keypair/sign/verify cycle bench ==========\n", ML_KEM_MODE);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_keypair(pk, sk);
  }
  print_results("ML-KEM keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_enc(ct, key, pk);
  }
  print_results("ML-KEM encaps: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_dec(key, ct, sk);
  }
  print_results("ML-KEM decaps: ", t, NTESTS);

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

  printf("============== Start doing ML-KEM-%d keypair/sign/verify bench ==============\n", ML_KEM_MODE);

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
  printf("ML-KEM keypair %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("ML-KEM keypair speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

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
  printf("ML-KEM encaps %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("ML-KEM encaps speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

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
  printf("ML-KEM decaps %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("ML-KEM decaps speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  puts("");

  printf("=============================== Finish ============================\n\n");
}

int main(void)
{

  // all_cycle_bench();
  core_alg_cycle_bench();
  double bench_time = 3.0;
  kem_enc_dec_bench(bench_time);

  return 0;
}
