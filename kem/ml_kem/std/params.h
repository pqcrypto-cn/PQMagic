#ifndef PARAMS_H
#define PARAMS_H

#ifndef ML_KEM_MODE
#define ML_KEM_MODE 512
#endif

/* Don't change parameters below this line */
#if   (ML_KEM_MODE == 512)
#define ML_KEM_K 2
#define ML_KEM_NAMESPACE(s) pqmagic_ml_kem_512_std##s
#elif (ML_KEM_MODE == 768)
#define ML_KEM_K 3
#define ML_KEM_NAMESPACE(s) pqmagic_ml_kem_768_std##s
#elif (ML_KEM_MODE == 1024)
#define ML_KEM_K 4
#define ML_KEM_NAMESPACE(s) pqmagic_ml_kem_1024_std##s
#else
#error "ML_KEM_MODE must be in {512,768,1024}"
#endif


#define ML_KEM_N 256
#define ML_KEM_Q 3329


#define ML_KEM_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define ML_KEM_SSBYTES  32   /* size in bytes of shared key */

#define ML_KEM_POLYBYTES		384
#define ML_KEM_POLYVECBYTES	(ML_KEM_K * ML_KEM_POLYBYTES)

#if ML_KEM_K == 2
#define ML_KEM_ETA1 3
#define ML_KEM_POLYCOMPRESSEDBYTES    128
#define ML_KEM_POLYVECCOMPRESSEDBYTES (ML_KEM_K * 320)
#elif ML_KEM_K == 3
#define ML_KEM_ETA1 2
#define ML_KEM_POLYCOMPRESSEDBYTES    128
#define ML_KEM_POLYVECCOMPRESSEDBYTES (ML_KEM_K * 320)
#elif ML_KEM_K == 4
#define ML_KEM_ETA1 2
#define ML_KEM_POLYCOMPRESSEDBYTES    160
#define ML_KEM_POLYVECCOMPRESSEDBYTES (ML_KEM_K * 352)
#endif

#define ML_KEM_ETA2 2

#define ML_KEM_INDCPA_MSGBYTES       ML_KEM_SYMBYTES
#define ML_KEM_INDCPA_PUBLICKEYBYTES (ML_KEM_POLYVECBYTES + ML_KEM_SYMBYTES)
#define ML_KEM_INDCPA_SECRETKEYBYTES (ML_KEM_POLYVECBYTES)
#define ML_KEM_INDCPA_BYTES          (ML_KEM_POLYVECCOMPRESSEDBYTES \
                                     + ML_KEM_POLYCOMPRESSEDBYTES)

#define ML_KEM_PUBLICKEYBYTES  (ML_KEM_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define ML_KEM_SECRETKEYBYTES  (ML_KEM_INDCPA_SECRETKEYBYTES \
                               + ML_KEM_INDCPA_PUBLICKEYBYTES \
                               + 2*ML_KEM_SYMBYTES)
#define ML_KEM_CIPHERTEXTBYTES  ML_KEM_INDCPA_BYTES

#endif
