#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"

static int hex_value(int character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    character = tolower((unsigned char)character);
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    return -1;
}

static int read_hex_field(FILE *file, const char *field, unsigned char *output, size_t output_bytes)
{
    const size_t field_length = strlen(field);
    const size_t line_bytes = field_length + 3 + output_bytes * 2 + 2;
    char *line = malloc(line_bytes);
    int result = -1;

    if (line == NULL) {
        return -1;
    }
    while (fgets(line, (int)line_bytes, file) != NULL) {
        size_t index;
        const char *hex;

        if (strncmp(line, field, field_length) != 0 ||
            strncmp(line + field_length, " = ", 3) != 0) {
            continue;
        }
        hex = line + field_length + 3;
        for (index = 0; index < output_bytes; ++index) {
            const int high = hex_value(hex[index * 2]);
            const int low = hex_value(hex[index * 2 + 1]);
            if (high < 0 || low < 0) {
                goto cleanup;
            }
            output[index] = (unsigned char)((high << 4) | low);
        }
        result = 0;
        break;
    }

cleanup:
    free(line);
    return result;
}

int main(void)
{
    const size_t secret_key_bytes = (size_t)kem_get_sk_len_bytes();
    const size_t ciphertext_bytes = (size_t)kem_get_ct_len_bytes();
    const size_t shared_secret_bytes = (size_t)kem_get_ss_len_bytes();
    unsigned char *secret_key = malloc(secret_key_bytes);
    unsigned char *ciphertext = malloc(ciphertext_bytes);
    unsigned char *expected = malloc(shared_secret_bytes);
    unsigned char *actual = malloc(shared_secret_bytes);
    unsigned long long actual_bytes = 0;
    FILE *file = fopen(QIMEN_KAT_FILE, "r");
    int result = 1;

    if (secret_key == NULL || ciphertext == NULL || expected == NULL || actual == NULL || file == NULL) {
        fputs("QIMEN-PIKE KAT setup failed\n", stderr);
        goto cleanup;
    }
    if (read_hex_field(file, "SK", secret_key, secret_key_bytes) != 0 ||
        read_hex_field(file, "CT", ciphertext, ciphertext_bytes) != 0 ||
        read_hex_field(file, "SS", expected, shared_secret_bytes) != 0) {
        fputs("QIMEN-PIKE KAT parse failed\n", stderr);
        goto cleanup;
    }
    if (kem_dec(secret_key, secret_key_bytes, ciphertext, ciphertext_bytes,
                actual, &actual_bytes) != 0 ||
        actual_bytes != shared_secret_bytes ||
        memcmp(actual, expected, shared_secret_bytes) != 0) {
        fputs("QIMEN-PIKE KAT mismatch\n", stderr);
        goto cleanup;
    }

    puts("QIMEN-PIKE KAT passed");
    result = 0;

cleanup:
    if (file != NULL) {
        fclose(file);
    }
    free(actual);
    free(expected);
    free(ciphertext);
    free(secret_key);
    return result;
}
