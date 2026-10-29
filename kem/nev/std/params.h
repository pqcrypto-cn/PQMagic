#ifndef PARAMS_H
#define PARAMS_H

// #define PARAMS 3 //change this to switch the parameter set


#if (PARAMS == 1) //NEV-512-769-C
#define NTT_DIM 128
#define PARAM_N 512
#define ETA_F 1
#define ETA_G 2
#define ETA_E 2
#define POLY_BYTES 615
#define SEED_BYTES 16
#define PARAM_Q 769
#define QINV 64769 // q^-1 mod 2^16
#define QBITS 10
#define COMPRESS 1
#elif (PARAMS == 2) //NEV-1024-769-C
#define NTT_DIM 128
#define PARAM_N 1024
#define ETA_F 1
#define ETA_G 8
#define ETA_E 2
#define POLY_BYTES 1229
#define SEED_BYTES 32
#define PARAM_Q 769
#define QINV 64769 // q^-1 mod 2^16
#define QBITS 10
#define COMPRESS 1
#elif (PARAMS == 3) //NEV-2048-769-C
#define NTT_DIM 128
#define PARAM_N 2048
#define ETA_F 8
#define ETA_G 8
#define ETA_E 1
#define POLY_BYTES 2458
#define SEED_BYTES 64
#define PARAM_Q 769
#define QINV 64769 // q^-1 mod 2^16
#define QBITS 10
#define COMPRESS 1
#elif (PARAMS == 4) //NEV-512-1409
#define NTT_DIM 64
#define PARAM_N 512
#define ETA_F 3
#define ETA_G 3
#define ETA_R 3
#define ETA_E 3
#define POLY_BYTES 672
#define SEED_BYTES 16
#define PARAM_Q 1409
#define QINV 14977 // q^-1 mod 2^16
#define QBITS 11
#define COMPRESS 0
#elif (PARAMS == 5) //NEV-1024-1409
#define NTT_DIM 64
#define PARAM_N 1024
#define ETA_F 2
#define ETA_G 2
#define ETA_R 2
#define ETA_E 2
#define POLY_BYTES 1344
#define SEED_BYTES 32
#define PARAM_Q 1409
#define QINV 14977 // q^-1 mod 2^16
#define QBITS 11
#define COMPRESS 0
#elif (PARAMS == 6) //NEV-2048-1409
#define NTT_DIM 64
#define PARAM_N 2048
#define ETA_F 9     //Ternary 1/3
#define ETA_G 9
#define ETA_R 9
#define ETA_E 2
#define POLY_BYTES 2688
#define SEED_BYTES 64
#define PARAM_Q 1409
#define QINV 14977 // q^-1 mod 2^16
#define QBITS 11
#define COMPRESS 0
#elif (PARAMS == 7) //NEV-512-3329
#define NTT_DIM 128
#define PARAM_N 512
#define ETA_F 7
#define ETA_G 7
#define ETA_R 7
#define ETA_E 7
#define POLY_BYTES 768
#define SEED_BYTES 16
#define PARAM_Q 3329
#define QINV 62209 // q^-1 mod 2^16
#define QBITS 12
#define COMPRESS 0
#elif (PARAMS == 8) //NEV-1024-3329
#define NTT_DIM 128
#define PARAM_N 1024
#define ETA_F 4
#define ETA_G 4
#define ETA_R 4
#define ETA_E 4
#define POLY_BYTES 1536
#define SEED_BYTES 32
#define PARAM_Q 3329
#define QINV 62209 // q^-1 mod 2^16
#define QBITS 12
#define COMPRESS 0
#elif (PARAMS == 9) //NEV-2048-3329
#define NTT_DIM 128
#define PARAM_N 2048
#define ETA_F 2
#define ETA_G 3
#define ETA_R 2
#define ETA_E 3
#define POLY_BYTES 3072
#define SEED_BYTES 64
#define PARAM_Q 3329
#define QINV 62209 // q^-1 mod 2^16
#define QBITS 12
#define COMPRESS 0
#elif (PARAMS == 10) //NEV-512-769
#define NTT_DIM 128
#define PARAM_N 512
#define ETA_F 1
#define ETA_G 2
#define ETA_R 9
#define ETA_E 2
#define POLY_BYTES 615
#define SEED_BYTES 16
#define PARAM_Q 769
#define QINV 64769 // q^-1 mod 2^16
#define QBITS 10
#define COMPRESS 0
#elif (PARAMS == 11) //NEV-1024-769
#define NTT_DIM 128
#define PARAM_N 1024
#define ETA_F 1
#define ETA_G 8
#define ETA_R 9
#define ETA_E 2
#define POLY_BYTES 1229
#define SEED_BYTES 32
#define PARAM_Q 769
#define QINV 64769 // q^-1 mod 2^16
#define QBITS 10
#define COMPRESS 0
#elif (PARAMS == 12) //NEV-2048-769
#define NTT_DIM 128
#define PARAM_N 2048
#define ETA_F 8
#define ETA_G 8
#define ETA_R 9
#define ETA_E 1
#define POLY_BYTES 2458
#define SEED_BYTES 64
#define PARAM_Q 769
#define QINV 64769 // q^-1 mod 2^16
#define QBITS 10
#define COMPRESS 0
#endif

#define RNG_SEED_BYTES 48

#if COMPRESS == 1

#define PKE_OW_PK_BYTES POLY_BYTES
#define PKE_OW_SK_BYTES POLY_BYTES
#define PKE_OW_CT_BYTES PARAM_N

#define KEM_CPA_PK_BYTES POLY_BYTES
#define KEM_CPA_SK_BYTES POLY_BYTES
#define KEM_CPA_CT_BYTES PARAM_N

#define PKE_CPA_PK_BYTES POLY_BYTES
#define PKE_CPA_SK_BYTES POLY_BYTES
#define PKE_CPA_CT_BYTES (PARAM_N + SEED_BYTES)

#define KEM_CCA_PK_BYTES POLY_BYTES
#define KEM_CCA_SK_BYTES (PKE_OW_SK_BYTES + KEM_CCA_PK_BYTES + SEED_BYTES)
#define KEM_CCA_CT_BYTES PARAM_N

#define PKE_CCA_PK_BYTES POLY_BYTES
#define PKE_CCA_SK_BYTES (PKE_OW_SK_BYTES + PKE_CCA_PK_BYTES + SEED_BYTES)
#define PKE_CCA_CT_BYTES (PARAM_N + SEED_BYTES)

#else

#define PKE_OW_PK_BYTES POLY_BYTES
#define PKE_OW_SK_BYTES POLY_BYTES
#define PKE_OW_CT_BYTES POLY_BYTES

#define KEM_CPA_PK_BYTES POLY_BYTES
#define KEM_CPA_SK_BYTES POLY_BYTES
#define KEM_CPA_CT_BYTES POLY_BYTES

#define PKE_CPA_PK_BYTES POLY_BYTES
#define PKE_CPA_SK_BYTES POLY_BYTES
#define PKE_CPA_CT_BYTES (POLY_BYTES + SEED_BYTES)

#define KEM_CCA_PK_BYTES POLY_BYTES
#define KEM_CCA_SK_BYTES (PKE_OW_SK_BYTES + KEM_CCA_PK_BYTES + SEED_BYTES)
#define KEM_CCA_CT_BYTES POLY_BYTES

#define PKE_CCA_PK_BYTES POLY_BYTES
#define PKE_CCA_SK_BYTES (PKE_OW_SK_BYTES + PKE_CCA_PK_BYTES + SEED_BYTES)
#define PKE_CCA_CT_BYTES (POLY_BYTES + SEED_BYTES)

#endif

#endif
