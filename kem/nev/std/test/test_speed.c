#include <stdio.h>
#include <time.h>

#include "api.h"
#include "cca.h"

#define ITERATIONS 10

static double elapsed_seconds(clock_t begin, clock_t end)
{
    return (double)(end - begin) / CLOCKS_PER_SEC;
}

int main(void)
{
    unsigned char public_key[KEM_PUBLICKEYBYTES];
    unsigned char secret_key[KEM_SECRETKEYBYTES];
    unsigned char ciphertext[KEM_CIPHERTEXTBYTES];
    unsigned char shared_secret[KEM_BYTES];
    clock_t begin;
    clock_t end;

    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i) {
        kem_cca_keygen(public_key, secret_key);
    }
    end = clock();
    printf("NEV keygen: %.3f ms/op\n", 1000.0 * elapsed_seconds(begin, end) / ITERATIONS);

    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i) {
        kem_cca_enc(shared_secret, ciphertext, public_key);
    }
    end = clock();
    printf("NEV encaps: %.3f ms/op\n", 1000.0 * elapsed_seconds(begin, end) / ITERATIONS);

    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i) {
        kem_cca_dec(shared_secret, ciphertext, secret_key);
    }
    end = clock();
    printf("NEV decaps: %.3f ms/op\n", 1000.0 * elapsed_seconds(begin, end) / ITERATIONS);
    return 0;
}
