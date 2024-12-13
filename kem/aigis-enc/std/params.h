#ifndef PARAMS_H
#define PARAMS_H

#include "config.h"

#if (PARAMS == 1) 

#define PARAM_N 256
#define NLOG 8
#define PARAM_Q 7681
#define QINV 57857 // q^-1 mod 2^16
#define QBITS 13
#define REJ_UNIFORM_BYTES 480 //fail with prob. less than 2^-18
#define PARAM_K 2
#define ETA_S 4
#define ETA_E 8
#define POLY_BYTES 416
#define BITS_PK 10
#define BITS_C1 10
#define BITS_C2 3
#define SEED_BYTES 32

#elif (PARAMS == 2) 

#define PARAM_N 256
#define NLOG 8
#define PARAM_Q 7681
#define QINV 57857 // q^-1 mod 2^16
#define QBITS 13
#define REJ_UNIFORM_BYTES 480 //fail with prob. less than 2^-18
#define PARAM_K 3
#define ETA_S 1
#define ETA_E 4
#define POLY_BYTES 416
#define BITS_PK 9
#define BITS_C1 9
#define BITS_C2 4
#define SEED_BYTES 32

#elif (PARAMS == 3) 

#define PARAM_N 256
#define NLOG 8
#define PARAM_Q 7681
#define QINV 57857 // q^-1 mod 2^16
#define QBITS 13
#define REJ_UNIFORM_BYTES 480 //fail with prob. less than 2^-18
#define PARAM_K 3
#define ETA_S 2
#define ETA_E 4
#define POLY_BYTES 416
#define BITS_PK 10
#define BITS_C1 10
#define BITS_C2 3
#define SEED_BYTES 32

#elif (PARAMS == 4)  

#define PARAM_N 256
#define NLOG 8
#define PARAM_Q 7681
#define QINV 57857 // q^-1 mod 2^16
#define QBITS 13
#define REJ_UNIFORM_BYTES 480 //fail with prob. less than 2^-18
#define PARAM_K 4
#define ETA_S 3
#define ETA_E 8
#define POLY_BYTES 416
#define BITS_PK 11
#define BITS_C1 11
#define BITS_C2 5
#define SEED_BYTES 32

#else
#error "PARAMS must be in {1,2,3,4}"
#endif

#define RNG_SEED_BYTES 48
#define POLYVEC_BYTES (PARAM_K * POLY_BYTES) 
#define POLY_COMPRESSED_BYTES (BITS_C2 *PARAM_N/8)
#define PK_POLYVEC_COMPRESSED_BYTES  (BITS_PK *PARAM_K *PARAM_N/8)
#define CT_POLYVEC_COMPRESSED_BYTES  (BITS_C1 *PARAM_K *PARAM_N/8)
#define PK_BYTES (SEED_BYTES + PK_POLYVEC_COMPRESSED_BYTES)
#define SK_BYTES (POLYVEC_BYTES + PK_BYTES + SEED_BYTES + SEED_BYTES) //use mulit-target resisitant and implicit rejection
#define CT_BYTES (CT_POLYVEC_COMPRESSED_BYTES + POLY_COMPRESSED_BYTES)

#define KEM_SECRETKEYBYTES  SK_BYTES
#define KEM_PUBLICKEYBYTES  PK_BYTES
#define KEM_CIPHERTEXTBYTES CT_BYTES
#define KEM_SSBYTES         SEED_BYTES

#endif
