#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "api.h"
#include "utils/cpucycles.h"
#include "utils/speed_print.h"

#define NTESTS 10000

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
  uint8_t coins[RNDBYTES];
  memset(coins, 1, RNDBYTES);
  
  printf("============ Start doing keypair/sign/verify cycle bench ==========\n");

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_keypair(pk, sk);
  }
  print_results("Keypair:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_signature_internal(sm, &smlen, sm, CRHBYTES, coins, sk);
  }
  print_results("Sign:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_verify_internal(sm, CRYPTO_BYTES, sm, CRHBYTES, pk);
  }
  print_results("Verify:", t, NTESTS);

  printf("=============================== Finish ============================\n\n");

  return;
}

void core_alg_benchmark(double bench_time) {
  size_t smlen;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sm[CRYPTO_BYTES];
  uint8_t coins[RNDBYTES];
  memset(coins, 1, RNDBYTES);

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

  printf("Perform Keypair %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("Keypair speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  printf("Keypair speed: %10.3lf us/time\n", (((double)clk2)) / (n) );


  puts("");


  n = 0;
  e = 16;

  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_sign_signature_internal(sm, &smlen, sm, CRHBYTES, coins, sk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);

  printf("Perform Sign %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("Sign speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  printf("Sign speed: %10.3lf us/time\n", (((double)clk2)) / (n) );

  puts("");

  n = 0;
  e = 16;

  clk1 = clock();
  do {
    for (i = 0; i < e; i++) {
      crypto_sign_verify_internal(sm, CRYPTO_BYTES, sm, CRHBYTES, pk);
    }
    clk2 = clock() - clk1;
    n += e;
    e <<= 1;
  } while ((double)clk2 / CLOCKS_PER_SEC < bench_time);

  printf("Perform Verify %lf times in %lf s.\n", n, (double)clk2 / CLOCKS_PER_SEC);

  printf("Verify speed: %10.3lf times/s\n", (n) / (((double)clk2) / CLOCKS_PER_SEC));

  printf("Verify speed: %10.3lf us/time\n", (((double)clk2)) / (n) );

  printf("============================== Finish =============================\n\n");

}

int main(void)
{

  double bench_time = 3.0;
  // cycle_bench();
  core_alg_cycle_bench();
  core_alg_benchmark(bench_time);
  
  return 0;
}
