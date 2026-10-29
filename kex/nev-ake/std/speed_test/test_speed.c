#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ake.h"
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
#include "owkem.h"


#define NTESTS 30000


int nev_test();
int compare(const uint8_t *s1, const uint8_t *s2, int length);


int main() {
    unsigned int i;
    unsigned char pki[CRYPTO_PUBLICKEYBYTES + 32] = {0};
    unsigned char ski[CRYPTO_SECRETKEYBYTES + 32] = {0};
    unsigned char pkj[CRYPTO_PUBLICKEYBYTES + 32] = {0};
    unsigned char skj[CRYPTO_SECRETKEYBYTES + 32] = {0};
    unsigned char M[AKE_M1_BYTES] = {0};
    unsigned char st[AKE_ST_BYTES] = {0};
    unsigned char M_prime[AKE_M2_BYTES] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES + 32] = {0};
    unsigned char key[CRYPTO_BYTES] = {0};
    unsigned char K[SEED_BYTES] = {0};
    unsigned char K_prime[SEED_BYTES] = {0};
    unsigned char idj[SEED_BYTES] = {0};
    unsigned char idi[SEED_BYTES] = {0};
    unsigned char mu[CRYPTO_BYTES] = {0};
    uint64_t t0[NTESTS], t1[NTESTS], t2[NTESTS], t3[NTESTS];
    unsigned char entropy_input[48];
    poly g, f, invf, h;
    int z;

    ake_keygen(pki, ski, pkj, skj);
    ake_init(M, st, ski, pkj);
    ake_der_response(M_prime, K_prime, idi, idj, skj, pki, M);
    ake_der_init(K, idi, idj, ski, pkj, st, M_prime);

    if (compare(K, K_prime, SEED_BYTES)) {
        for (i = 0; i < SEED_BYTES; ++i) {
            if (K[i] != K_prime[i]) {
                printf("ake correctness mismatch at test 0 byte %u: K=%#x, K_prime=%#x\n",
                       i, K[i], K_prime[i]);
                break;
            }
        }
    } else {
        printf("ake correctness test passed\n");
    }

    nev_test();


    printf("*****************************\n");
#if COMPRESS == 0
    printf("NEV-%d-%d-ref\n",PARAM_N,PARAM_Q);
#else
    printf("NEV-%d-%d-ref-c\n",PARAM_N,PARAM_Q);
#endif
    printf("PK Sizes:%d\n",CRYPTO_PUBLICKEYBYTES);
    printf("SK Sizes:%d\n",CRYPTO_SECRETKEYBYTES);
    printf("CT Sizes:%d\n",CRYPTO_CIPHERTEXTBYTES);
    printf("AKE_COMMUNICATION_INITIATOR_BYTES:%d\n",AKE_COMMUNICATION_INITIATOR_BYTES);
    printf("AKE_COMMUNICATION_RESPONSE_BYTES:%d\n",AKE_COMMUNICATION_RESPONSE_BYTES);
    printf("TOTAL Sizes:%d\n",CRYPTO_PUBLICKEYBYTES + CRYPTO_CIPHERTEXTBYTES);
    printf("*****************************\n");


    for (i = 0; i < NTESTS; i++) {
        t0[i] = cpucycles();
        ake_keygen(pki, ski, pkj, skj);
        t0[i] =cpucycles() - t0[i];

        t1[i] = cpucycles();
        ake_init(M, st, ski, pkj);
        t1[i] =cpucycles() - t1[i];

        t2[i] = cpucycles();
        ake_der_response(M_prime, K_prime, idi, idj, skj, pki, M);
        t2[i] =cpucycles() - t2[i];

        t3[i] = cpucycles();
        ake_der_init(K, idi, idj, ski, pkj, st, M_prime);
        t3[i] =cpucycles() - t3[i];
    }
    print_results("ake_keygen: ", t0, NTESTS);
    print_results("ake_init: ", t1, NTESTS);
    print_results("ake_der_response: ", t2, NTESTS);
    print_results("ake_der_init: ", t3, NTESTS);

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
