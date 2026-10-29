#include <stdio.h>
#include <string.h>

#include "api.h"

int main(void)
{
    unsigned char public_key[KEM_PUBLICKEYBYTES];
    unsigned char secret_key[KEM_SECRETKEYBYTES];
    unsigned char ciphertext[KEM_CIPHERTEXTBYTES];
    unsigned char encapsulated[KEM_BYTES];
    unsigned char decapsulated[KEM_BYTES];

    if (mkem_keygen(public_key, secret_key) != 0 ||
        mkem_enc(public_key, encapsulated, ciphertext) != 0 ||
        mkem_dec(secret_key, ciphertext, decapsulated) != 0) {
        fputs("Aigis-Enc+ operation failed\n", stderr);
        return 1;
    }
    if (memcmp(encapsulated, decapsulated, sizeof(encapsulated)) != 0) {
        fputs("Aigis-Enc+ shared-secret mismatch\n", stderr);
        return 1;
    }

    puts("Aigis-Enc+ correctness test passed");
    return 0;
}
