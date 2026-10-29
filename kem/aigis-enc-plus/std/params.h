#ifndef PARAMS_H
#define PARAMS_H

// #define PARAMS 1//change this to switch the parameter set

#define NTT_DIM 128
#define PARAM_Q 3329
#define QINV 62209 // q^-1 mod 2^16
#define QBITS 12

#if (PARAMS == 1)  
#define PARAM_N 512
#define REJ_UNIFORM_BYTES 1056 //fail with prob. less than 2^-26
#define PARAM_K 1
#define ETA_S 5
#define ETA_E 6
#define ETAS_BYTES (ETA_S*PARAM_N/4)
#define ETAE_BYTES (ETA_E*PARAM_N/4)
#define POLY_BYTES 768
#define BITS_PK 10
#define BITS_C1 10
#define BITS_C2 4
//#define MSG_BYTES 16
#define MSG_BYTES 16
#define SEED_BYTES 16
#define RNG_SEED_BYTES 48
#elif (PARAMS == 2)  
#define PARAM_N 1024
#define REJ_UNIFORM_BYTES 2112 //fail with prob. less than 2^-26
#define PARAM_K 1
#define ETA_S 2
#define ETA_E 6
#define ETAS_BYTES (ETA_S*PARAM_N/4)
#define ETAE_BYTES (ETA_E*PARAM_N/4)
#define POLY_BYTES 1536
#define BITS_PK 10
#define BITS_C1 10
#define BITS_C2 3
#define MSG_BYTES 32
#define SEED_BYTES 32
#define RNG_SEED_BYTES 48
#elif (PARAMS == 3)  
#define PARAM_N 2048
#define REJ_UNIFORM_BYTES 4224 //fail with prob. less than 2^-26
#define PARAM_K 1
#define ETA_S 2
#define ETA_E 3
#define ETAS_BYTES (ETA_S*PARAM_N/4)
#define ETAE_BYTES (ETA_E*PARAM_N/4)
#define POLY_BYTES 3072
#define BITS_PK 10
#define BITS_C1 10
#define BITS_C2 4
#define MSG_BYTES 64
#define SEED_BYTES 64
#define RNG_SEED_BYTES 80

#else
#error "PARAMS must be in {1,2,3}"
#endif


#define POLYVEC_BYTES (PARAM_K * POLY_BYTES) 
#define POLY_COMPRESSED_BYTES (BITS_C2 *PARAM_N/8)
#if PARAM_Q == 3329
#define PK_POLYVEC_COMPRESSED_BYTES  (BITS_PK *PARAM_K *PARAM_N/8)
#define CT_POLYVEC_COMPRESSED_BYTES  (BITS_C1 *PARAM_K *PARAM_N/8)
#endif
#define PK_BYTES (SEED_BYTES + PK_POLYVEC_COMPRESSED_BYTES)
#define SK_BYTES (POLYVEC_BYTES + PK_BYTES + SEED_BYTES + SEED_BYTES) //use mulit-target resisitant and implicit rejection
#define CT_BYTES (CT_POLYVEC_COMPRESSED_BYTES + POLY_COMPRESSED_BYTES)
#endif
