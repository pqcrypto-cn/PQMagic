#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include "../api.h"
#include "utils/cpucycles.h"
#include "utils/speed_print.h"

#define NTESTS 10
#define SPX_MLEN 32

uint64_t t[NTESTS];
void core_alg_cycle_bench(void);
void core_alg_benchmark(double bench_time);

void core_alg_cycle_bench(void)
{
  unsigned int i;
  size_t smlen;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sm[CRYPTO_BYTES];
  printf("============ Start doing keypair/sign/verify cycle bench ==========\n");

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_keypair(pk, sk);
  }
  print_results("SPHINCS-Alpha keypair:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_signature(sm, &smlen, sm, SPX_MLEN, sk);
  }
  print_results("SPHINCS-Alpha sign:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_verify(sm, CRYPTO_BYTES, sm, SPX_MLEN, pk);
  }
  print_results("SPHINCS-Alpha verify:", t, NTESTS);

  printf("=============================== Finish ============================\n\n");

  return;
}

void core_alg_benchmark(double bench_time) {
  size_t smlen;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sm[CRYPTO_BYTES];

  printf("============== Start doing keypair/sign/verify bench ==============\n");
  
  clock_t clk1, clk2;
  uint64_t i, e;
  double n;

  n = 0;
  e = 16;

  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_sign_keypair(pk, sk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);

  printf("SPHINCS-Alpha keypair %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("SPHINCS-Alpha keypair speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  puts("");


  n = 0;
  e = 16;

  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_sign_signature(sm, &smlen, sm, SPX_MLEN, sk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);

  printf("SPHINCS-Alpha sign %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("SPHINCS-Alpha sign speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  puts("");

  n = 0;
  e = 16;

  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_sign_verify(sm, CRYPTO_BYTES, sm, SPX_MLEN, pk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);

  printf("SPHINCS-Alpha verify %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("SPHINCS-Alpha verify speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  printf("============================== Finish =============================\n\n");

}

int main(void)
{

  double bench_time = 3.0;
  core_alg_cycle_bench();
  core_alg_benchmark(bench_time);
  
  return 0;
}
