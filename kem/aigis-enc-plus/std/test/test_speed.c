#include <stdio.h>
#include <time.h>

#include "api.h"

#define ITERATIONS 10

static double milliseconds(clock_t begin, clock_t end)
{
    return 1000.0 * (double)(end - begin) / CLOCKS_PER_SEC / ITERATIONS;
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
    for (int i = 0; i < ITERATIONS; ++i) mkem_keygen(public_key, secret_key);
    end = clock();
    printf("Aigis-Enc+ keygen: %.3f ms/op\n", milliseconds(begin, end));
    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i) mkem_enc(public_key, shared_secret, ciphertext);
    end = clock();
    printf("Aigis-Enc+ encaps: %.3f ms/op\n", milliseconds(begin, end));
    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i) mkem_dec(secret_key, ciphertext, shared_secret);
    end = clock();
    printf("Aigis-Enc+ decaps: %.3f ms/op\n", milliseconds(begin, end));
    return 0;
}
