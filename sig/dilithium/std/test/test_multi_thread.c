#include <stdint.h>
#include "sign.h"
#include "poly.h"
#include "polyvec.h"
#include "params.h"
#include "utils/cpucycles.h"
#include "utils/speed_print.h"

#include <pthread.h>
#include <stdio.h>

#define NTESTS 1000
void thread_func(void);

void thread_func(void)
{
    uint64_t t[NTESTS];
    unsigned int i;
    size_t smlen;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sm[CRYPTO_BYTES + CRHBYTES];
    uint8_t seed[CRHBYTES] = {0};
    polyvecl mat[K];
    poly *a = &mat[0].vec[0];
    poly *b = &mat[0].vec[1];
    poly *c = &mat[0].vec[2];
    int ret;
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      polyvec_matrix_expand(mat, seed);
    }
    print_results("polyvec_matrix_expand:", t, NTESTS);
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      poly_uniform_eta(a, seed, 0);
    }
    print_results("poly_uniform_eta:", t, NTESTS);
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      poly_uniform_gamma1(a, seed, 0);
    }
    print_results("poly_uniform_gamma1:", t, NTESTS);
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      poly_ntt(a);
    }
    print_results("poly_ntt:", t, NTESTS);
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      poly_invntt_tomont(a);
    }
    print_results("poly_invntt_tomont:", t, NTESTS);
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      poly_pointwise_montgomery(c, a, b);
    }
    print_results("poly_pointwise_montgomery:", t, NTESTS);
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      poly_challenge(c, seed);
    }
    print_results("poly_challenge:", t, NTESTS);
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      crypto_sign_keypair(pk, sk);
    }
    print_results("Keypair:", t, NTESTS);
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      crypto_sign_signature(sm, &smlen, seed, CRHBYTES, sk);
    }
    print_results("Sign:", t, NTESTS);
    
    for(i = 0; i < NTESTS; ++i) {
      t[i] = cpucycles();
      ret = crypto_sign_verify(sm, CRYPTO_BYTES, seed, CRHBYTES, pk);
      if (ret < 0) {
        printf("err\n");
      } 
    }
    print_results("Verify:", t, NTESTS);
    
    return;

}

int main(int argc, char **argv)
{
    pthread_t th[8];
    int num;

    num = atoi(argv[1]);

    for (int i = 0; i < num; i++) {
        pthread_create(&th[i], NULL, thread_func, NULL);
    }

    sleep(10);

    return 0;
}
