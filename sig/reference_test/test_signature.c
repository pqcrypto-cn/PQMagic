#include <stdio.h>
#include <stdlib.h>

#include "SIG_AlgorithmInstance.h"

int main(void)
{
    static unsigned char message[] = "PQMagic reference signature test";
    unsigned long long public_key_length = sig_get_pk_len_bytes();
    unsigned long long secret_key_length = sig_get_sk_len_bytes();
    unsigned long long signature_length = sig_get_sn_len_bytes();
    unsigned char *public_key = calloc(public_key_length, 1);
    unsigned char *secret_key = calloc(secret_key_length, 1);
    unsigned char *signature = calloc(signature_length, 1);
    int status = 1;

    if (public_key == NULL || secret_key == NULL || signature == NULL) {
        fputs("allocation failed\n", stderr);
        goto cleanup;
    }
    if (sig_keygen(public_key, &public_key_length, secret_key, &secret_key_length) != 0 ||
        sig_sign(secret_key, secret_key_length, message, sizeof(message),
                 signature, &signature_length) != 0 ||
        sig_verify(public_key, public_key_length, signature, signature_length,
                   message, sizeof(message)) != 0) {
        fputs("reference signature correctness test failed\n", stderr);
        goto cleanup;
    }

    puts("reference signature correctness test passed");
    status = 0;

cleanup:
    free(signature);
    free(secret_key);
    free(public_key);
    return status;
}
