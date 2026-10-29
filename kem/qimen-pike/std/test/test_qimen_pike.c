#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"

int main(void)
{
    const size_t public_key_bytes = (size_t)kem_get_pk_len_bytes();
    const size_t secret_key_bytes = (size_t)kem_get_sk_len_bytes();
    const size_t ciphertext_bytes = (size_t)kem_get_ct_len_bytes();
    const size_t shared_secret_bytes = (size_t)kem_get_ss_len_bytes();
    unsigned char *public_key = malloc(public_key_bytes);
    unsigned char *secret_key = malloc(secret_key_bytes);
    unsigned char *ciphertext = malloc(ciphertext_bytes);
    unsigned char *encapsulated = malloc(shared_secret_bytes);
    unsigned char *decapsulated = malloc(shared_secret_bytes);
    unsigned long long actual_public_key_bytes = 0;
    unsigned long long actual_secret_key_bytes = 0;
    unsigned long long actual_ciphertext_bytes = 0;
    unsigned long long actual_encapsulated_bytes = 0;
    unsigned long long actual_decapsulated_bytes = 0;
    int result = 1;

    if (public_key == NULL || secret_key == NULL || ciphertext == NULL ||
        encapsulated == NULL || decapsulated == NULL) {
        fputs("QIMEN-PIKE allocation failed\n", stderr);
        goto cleanup;
    }
    if (kem_keygen(public_key, &actual_public_key_bytes,
                   secret_key, &actual_secret_key_bytes) != 0 ||
        kem_enc(public_key, actual_public_key_bytes,
                encapsulated, &actual_encapsulated_bytes,
                ciphertext, &actual_ciphertext_bytes) != 0 ||
        kem_dec(secret_key, actual_secret_key_bytes,
                ciphertext, actual_ciphertext_bytes,
                decapsulated, &actual_decapsulated_bytes) != 0) {
        fputs("QIMEN-PIKE operation failed\n", stderr);
        goto cleanup;
    }
    if (actual_public_key_bytes != public_key_bytes ||
        actual_secret_key_bytes != secret_key_bytes ||
        actual_ciphertext_bytes != ciphertext_bytes ||
        actual_encapsulated_bytes != shared_secret_bytes ||
        actual_decapsulated_bytes != shared_secret_bytes ||
        memcmp(encapsulated, decapsulated, shared_secret_bytes) != 0) {
        fputs("QIMEN-PIKE result mismatch\n", stderr);
        goto cleanup;
    }

    puts("QIMEN-PIKE correctness test passed");
    result = 0;

cleanup:
    free(decapsulated);
    free(encapsulated);
    free(ciphertext);
    free(secret_key);
    free(public_key);
    return result;
}
