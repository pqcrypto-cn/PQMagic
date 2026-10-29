#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pack.h"
#include "../api.h"
#include "../randombytes.h"
#include "cpucycles.h"
#include "ntt.h"
#include "reduce.h"
#include "../owpke.h"
#include "../cca.h"
#include "../cpa.h"
#include "speed_print.h"
#include "../poly.h"


#define NTESTS 10000

uint64_t t[NTESTS];

int nev_test();

int main() {
    unsigned int i;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES + 32] = {0};
    unsigned char sk[CRYPTO_SECRETKEYBYTES + 32] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES + 32] = {0};
    unsigned char key[CRYPTO_BYTES] = {0};
    unsigned char mu[CRYPTO_BYTES] = {0};
    unsigned char entropy_input[48];
    poly g, f, invf, h;
    int z;

    // nev_test();

    printf("*****************************\n");
#if COMPRESS == 0
    printf("NEV-%d-%d-ref\n",PARAM_N,PARAM_Q);
#else
    printf("NEV-%d-%d-ref-c\n",PARAM_N,PARAM_Q);
#endif
    printf("PK Sizes:%d\n",CRYPTO_PUBLICKEYBYTES);
    printf("SK Sizes:%d\n",CRYPTO_SECRETKEYBYTES);
    printf("CT Sizes:%d\n",CRYPTO_CIPHERTEXTBYTES);
    printf("TOTAL Sizes:%d\n",CRYPTO_PUBLICKEYBYTES + CRYPTO_CIPHERTEXTBYTES);
    printf("*****************************\n");


    // for (i = 0; i < NTESTS; i++) {
    //     t[i] = cpucycles();
    //     kem_cpa_keygen(pk, sk);
    // }
    // print_results("kem_cpa_keygen: ", t, NTESTS);
    //
    // for (i = 0; i < NTESTS; i++) {
    //     t[i] = cpucycles();
    //     kem_cpa_enc(ct, key, pk);
    // }
    // print_results("kem_cpa_enc: ", t, NTESTS);
    //
    // for (i = 0; i < NTESTS; i++) {
    //     t[i] = cpucycles();
    //     kem_cpa_dec(key, ct,  sk);
    // }
    // print_results("kem_cpa_dec: ", t, NTESTS);
    //
    // for (i = 0; i < NTESTS; i++) {
    //     t[i] = cpucycles();
    //     pke_cpa_keygen(pk, sk);
    // }
    // print_results("pke_cpa_keygen: ", t, NTESTS);
    //
    // for (i = 0; i < NTESTS; i++) {
    //     t[i] = cpucycles();
    //     pke_cpa_enc(ct, mu, pk);
    // }
    // print_results("pke_cpa_enc: ", t, NTESTS);
    //
    // for (i = 0; i < NTESTS; i++) {
    //     t[i] = cpucycles();
    //     pke_cpa_dec(mu, ct, sk);
    // }
    // print_results("pke_cpa_dec: ", t, NTESTS);

    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        kem_cca_keygen(pk, sk);
    }
    print_results("kem_cca_keygen: ", t, NTESTS);

    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        kem_cca_enc(key, ct, pk);
    }
    print_results("kem_cca_enc: ", t, NTESTS);

    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        if (kem_cca_dec(key, ct, sk)) printf("decryption failure!\n");
    }
    print_results("kem_cca_dec: ", t, NTESTS);

    // for (i = 0; i < NTESTS; i++) {
    //     t[i] = cpucycles();
    //     pke_cca_keygen(pk, sk);
    // }
    // print_results("pke_cca_keygen: ", t, NTESTS);
    //
    // for (i = 0; i < NTESTS; i++) {
    //     t[i] = cpucycles();
    //     pke_cca_enc(ct, mu, pk);
    // }
    // print_results("pke_cca_enc: ", t, NTESTS);
    //
    // for (i = 0; i < NTESTS; i++) {
    //     t[i] = cpucycles();
    //     pke_cca_dec(mu, ct, sk);
    // }
    // print_results("pke_cca_dec: ", t, NTESTS);

    return 0;
}

int compare(const uint8_t *s1, const uint8_t *s2, int length) {
    for (int i = 0; i < length; ++i) {
        if (s1[i] != s2[i]) return 1;
    }
    return 0;
}

int nev_test() {
    unsigned int i;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES + SEED_BYTES] = {0};
    unsigned char sk[CRYPTO_SECRETKEYBYTES + SEED_BYTES] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES + SEED_BYTES] = {0};
    unsigned char key[CRYPTO_BYTES + SEED_BYTES] = {0};
    unsigned char key2[CRYPTO_BYTES + SEED_BYTES] = {0};
    unsigned char mu[CRYPTO_BYTES + SEED_BYTES] = {0};
    unsigned char mu2[CRYPTO_BYTES + SEED_BYTES] = {0};

    for (i = 0; i < NTESTS; i++) {
        randombytes(mu, SEED_BYTES);
        ow_pke_keypair(pk, sk);
        ow_pke_enc(ct, mu, pk);
        ow_pke_dec(mu2, ct, sk);
        if (compare(mu, mu2,SEED_BYTES)) {
            printf("pke_ow message mismatch at %d\n", i);
                        //打印mu 和 mu2 的值
            return 1;
        }

        kem_cpa_keygen(pk, sk);
        kem_cpa_enc(ct, key, pk);
        kem_cpa_dec(key2, ct, sk);
        if (compare(key, key2,SEED_BYTES)) {
            printf("kem_cpa shared key mismatch at %d\n", i);
            return 1;
        }

        pke_cpa_keygen(pk, sk);
        pke_cpa_enc(ct, mu, pk);
        pke_cpa_dec(mu2, ct, sk);
        if (compare(mu, mu2,SEED_BYTES)) {
            printf("pke_cpa message mismatch at %d\n", i);
            return 1;
        }

        kem_cca_keygen(pk, sk);
        kem_cca_enc(key, ct, pk);
        kem_cca_dec(key2, ct, sk);
        if (compare(key, key2,SEED_BYTES)) {
            printf("kem_cca shared key mismatch at %d\n", i);
            return 1;
        }

        pke_cca_keygen(pk, sk);
        pke_cca_enc(ct, mu, pk);
        if(pke_cca_dec(mu2, ct, sk)) {
            printf("pke_cca decryption fail\n at %d", i);
            return 1;
        };
        if (compare(mu, mu2,SEED_BYTES)) {
            printf("pke_cca message mismatch\n at %d", i);
            return 1;
        }
    }

    return 0;
}
