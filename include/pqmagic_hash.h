#ifndef PQMAGIC_HASH_H
#define PQMAGIC_HASH_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "include/sm_config.h"

/**
 * Perform SM3 hash.
 */
size_t sm3(const uint8_t *data, size_t datalen, uint8_t dgst[SM3_DIGEST_LENGTH]);
/**
 * Perform HMAC based on SM3 hash function.
 */
size_t sm3_hmac(
    const uint8_t * data, size_t datalen, 
    const uint8_t * key, size_t key_len, 
    uint8_t mac[SM3_HMAC_SIZE]);

#endif
