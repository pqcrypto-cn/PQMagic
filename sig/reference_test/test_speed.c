#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "SIG_AlgorithmInstance.h"

static double milliseconds(clock_t begin, clock_t end)
{
    return 1000.0 * (double)(end - begin) / CLOCKS_PER_SEC;
}

int main(void)
{
    static unsigned char message[] = "PQMagic reference signature benchmark";
    unsigned long long public_key_length = sig_get_pk_len_bytes();
    unsigned long long secret_key_length = sig_get_sk_len_bytes();
    unsigned long long signature_length = sig_get_sn_len_bytes();
    unsigned char *public_key = calloc(public_key_length, 1);
    unsigned char *secret_key = calloc(secret_key_length, 1);
    unsigned char *signature = calloc(signature_length, 1);
    clock_t begin;
    clock_t end;

    if (public_key == NULL || secret_key == NULL || signature == NULL) return 1;

    begin = clock();
    sig_keygen(public_key, &public_key_length, secret_key, &secret_key_length);
    end = clock();
    printf("reference signature keygen: %.3f ms/op\n", milliseconds(begin, end));
    begin = clock();
    sig_sign(secret_key, secret_key_length, message, sizeof(message),
             signature, &signature_length);
    end = clock();
    printf("reference signature sign: %.3f ms/op\n", milliseconds(begin, end));
    begin = clock();
    sig_verify(public_key, public_key_length, signature, signature_length,
               message, sizeof(message));
    end = clock();
    printf("reference signature verify: %.3f ms/op\n", milliseconds(begin, end));

    free(signature);
    free(secret_key);
    free(public_key);
    return 0;
}
