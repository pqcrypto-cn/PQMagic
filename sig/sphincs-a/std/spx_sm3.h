#ifndef SPX_SM3_H
#define SPX_SM3_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "include/sm3_extended.h"
#include "include/pqmagic_hash.h"

#define SPX_SM3_BLOCK_BYTES SM3_BLOCK_SIZE
#define SPX_SM3_OUTPUT_BYTES SM3_DIGEST_LENGTH  /* This does not necessarily equal SPX_N */

#if SPX_SM3_OUTPUT_BYTES < SPX_N
    #error Linking against SM3 with N larger than 32 bytes is not supported
#endif

#define SPX_SM3_ADDR_BYTES 22

#endif
