#include <stdio.h>
#include <time.h>
#include "api.h"
#include "utils/randombytes.h"
#include "utils/cpucycles.h"
#include "utils/speed_print.h"

#define MLEN 64
#define NTESTS 10000

uint64_t t[NTESTS];
void cycle_bench(void);
void core_alg_benchmark(double bench_time);

void cycle_bench(void)
{
  unsigned int i;
  uint8_t sig[SIG_BYTES];
  uint8_t pk[SIG_PUBLICKEYBYTES];
  uint8_t sk[SIG_SECRETKEYBYTES];
  size_t sig_byts;

  printf("============ Start doing keypair/sign/verify cycle bench ==========\n");

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_keypair(pk, sk);
  }
  print_results("Aigis-sig keypair:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_signature(sig, &sig_byts, sig, MLEN, NULL, 0, sk);
  }
  print_results("Aigis-sig sign:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_verify(sig, SIG_BYTES, sig, MLEN, NULL, 0, pk);
  }
  print_results("Aigis-sig verify:", t, NTESTS);

  printf("=============================== Finish ============================\n\n");

  return;
}

void core_alg_benchmark(double bench_time) {
  uint8_t sig[SIG_BYTES];
  uint8_t pk[SIG_PUBLICKEYBYTES];
  uint8_t sk[SIG_SECRETKEYBYTES];
  size_t sig_byts;


  clock_t clk1, clk2;
  uint64_t i, e;
  double n;

  printf("============== Start doing keypair/sign/verify bench ==============\n");

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

  printf("Aigis-sig keypair %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("Aigis-sig keypair speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  // printf("Aigis-sig keypair speed: %10.3lf us/time\n\n", (((double)clk2)) / (n) );



  n = 0;
  e = 16;

  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_sign_signature(sig, &sig_byts, sig, MLEN, NULL, 0, sk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);

  printf("Aigis-sig sign %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("Aigis-sig sign speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  // printf("Aigis-sig sign speed: %10.3lf us/time\n\n", (((double)clk2)) / (n) );


  n = 0;
  e = 16;

  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_sign_verify(sig, SIG_BYTES, sig, MLEN, NULL, 0, pk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);

  printf("Aigis-sig verify %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("Aigis-sig verify speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  // printf("Aigis-sig verify speed: %10.3lf us/time\n", (((double)clk2)) / (n) );

  printf("============================== Finish =============================\n\n");
}

int main(void)
{

  cycle_bench();
  double bench_time = 3.0;
  core_alg_benchmark(bench_time);

  return 0;
}

