#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "KEM_AlgorithmInstance.h"

static double elapsed_milliseconds(clock_t start, clock_t end)
{
    return 1000.0 * (double)(end - start) / (double)CLOCKS_PER_SEC;
}

int main(void)
{
    const size_t public_key_bytes = (size_t)kem_get_pk_len_bytes();
    const size_t secret_key_bytes = (size_t)kem_get_sk_len_bytes();
    const size_t ciphertext_bytes = (size_t)kem_get_ct_len_bytes();
    const size_t shared_secret_bytes = (size_t)kem_get_ss_len_bytes();
    unsigned char *public_key = malloc(public_key_bytes);
    unsigned char *secret_key = malloc(secret_key_bytes);
    unsigned char *ciphertext = malloc(ciphertext_bytes);
    unsigned char *shared_secret = malloc(shared_secret_bytes);
    unsigned long long output_bytes = 0;
    unsigned long long secondary_output_bytes = 0;
    clock_t start;
    clock_t end;
    int result = 1;

    if (public_key == NULL || secret_key == NULL || ciphertext == NULL || shared_secret == NULL) {
        fputs("QIMEN-PIKE benchmark allocation failed\n", stderr);
        goto cleanup;
    }
    start = clock();
    if (kem_keygen(public_key, &output_bytes, secret_key, &secondary_output_bytes) != 0) {
        goto cleanup;
    }
    end = clock();
    printf("keygen: %.3f ms\n", elapsed_milliseconds(start, end));

    start = clock();
    if (kem_enc(public_key, public_key_bytes, shared_secret, &output_bytes,
                ciphertext, &secondary_output_bytes) != 0) {
        goto cleanup;
    }
    end = clock();
    printf("encaps: %.3f ms\n", elapsed_milliseconds(start, end));

    start = clock();
    if (kem_dec(secret_key, secret_key_bytes, ciphertext, ciphertext_bytes,
                shared_secret, &output_bytes) != 0) {
        goto cleanup;
    }
    end = clock();
    printf("decaps: %.3f ms\n", elapsed_milliseconds(start, end));
    result = 0;

cleanup:
    free(shared_secret);
    free(ciphertext);
    free(secret_key);
    free(public_key);
    return result;
}
