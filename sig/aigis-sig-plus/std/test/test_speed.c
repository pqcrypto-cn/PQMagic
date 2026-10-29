#include <stdio.h>
#include <time.h>

#include "api.h"

#define ITERATIONS 3

static double milliseconds(clock_t begin, clock_t end)
{
    return 1000.0 * (double)(end - begin) / CLOCKS_PER_SEC / ITERATIONS;
}

int main(void)
{
    static unsigned char message[] = "PQMagic Aigis-Sig+ benchmark";
    unsigned char public_key[SIG_PUBLICKEYBYTES];
    unsigned char secret_key[SIG_SECRETKEYBYTES];
    unsigned char signature[SIG_BYTES];
    unsigned long long signature_length = 0;
    clock_t begin;
    clock_t end;

    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i) msig_keygen(public_key, secret_key);
    end = clock();
    printf("Aigis-Sig+ keygen: %.3f ms/op\n", milliseconds(begin, end));
    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i)
        msig_sign(secret_key, message, sizeof(message), signature, &signature_length);
    end = clock();
    printf("Aigis-Sig+ sign: %.3f ms/op\n", milliseconds(begin, end));
    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i)
        msig_verf(public_key, signature, signature_length, message, sizeof(message));
    end = clock();
    printf("Aigis-Sig+ verify: %.3f ms/op\n", milliseconds(begin, end));
    return 0;
}
