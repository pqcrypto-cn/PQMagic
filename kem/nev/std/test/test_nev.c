#include <stdio.h>
#include <string.h>

#include "api.h"
#include "cca.h"

int main(void)
{
    unsigned char public_key[KEM_PUBLICKEYBYTES];
    unsigned char secret_key[KEM_SECRETKEYBYTES];
    unsigned char ciphertext[KEM_CIPHERTEXTBYTES];
    unsigned char encapsulated[KEM_BYTES];
    unsigned char decapsulated[KEM_BYTES];

    if (kem_cca_keygen(public_key, secret_key) != 0 ||
        kem_cca_enc(encapsulated, ciphertext, public_key) != 0 ||
        kem_cca_dec(decapsulated, ciphertext, secret_key) != 0) {
        fputs("NEV operation failed\n", stderr);
        return 1;
    }
    if (memcmp(encapsulated, decapsulated, sizeof(encapsulated)) != 0) {
        fputs("NEV shared-secret mismatch\n", stderr);
        return 1;
    }

    puts("NEV correctness test passed");
    return 0;
}
