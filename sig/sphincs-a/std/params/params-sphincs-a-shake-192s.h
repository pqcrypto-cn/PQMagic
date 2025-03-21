#ifndef SPX_PARAMS_H
#define SPX_PARAMS_H

/* Hash output length in bytes. */
#define SPX_N 24
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 63
/* Number of subtree layer. */
#define SPX_D 9
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 14
#define SPX_FORS_TREES 17
/* Winternitz parameter, */
#define SPX_WOTS_W 77

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* For clarity */
#define SPX_ADDR_BYTES 32
 

#define SPX_WOTS_LEN 32
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
    #error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* FORS parameters. */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES +\
                   SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

#include "../shake_offsets.h"

#endif
