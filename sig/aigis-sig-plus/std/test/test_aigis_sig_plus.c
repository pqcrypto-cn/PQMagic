#include <stdio.h>

#include "api.h"

int main(void)
{
    static const unsigned char message[] = "PQMagic Aigis-Sig+ test";
    unsigned char public_key[SIG_PUBLICKEYBYTES];
    unsigned char secret_key[SIG_SECRETKEYBYTES];
    unsigned char signature[SIG_BYTES];
    unsigned long long signature_length = 0;

    if (msig_keygen(public_key, secret_key) != 0 ||
        msig_sign(secret_key, (unsigned char *)message, sizeof(message),
                  signature, &signature_length) != 0 ||
        msig_verf(public_key, signature, signature_length,
                  (unsigned char *)message, sizeof(message)) != 0) {
        fputs("Aigis-Sig+ correctness test failed\n", stderr);
        return 1;
    }

    puts("Aigis-Sig+ correctness test passed");
    return 0;
}
