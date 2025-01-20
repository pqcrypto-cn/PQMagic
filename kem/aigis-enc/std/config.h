#ifndef CONFIG_H
#define CONFIG_H

#ifndef AIGIS_ENC_MODE
#define AIGIS_ENC_MODE 2
#endif

#define PARAMS AIGIS_ENC_MODE

#if (PARAMS == 1)
#define CRYPTO_ALGNAME "Aigis-enc-1"
#define AIGIS_ENC_NAMESPACE(s) pqmagic_aigis_enc_1_std_##s
#elif (PARAMS == 2)
#define CRYPTO_ALGNAME "Aigis-enc-2"
#define AIGIS_ENC_NAMESPACE(s) pqmagic_aigis_enc_2_std_##s
#elif (PARAMS == 3)
#define CRYPTO_ALGNAME "Aigis-enc-3"
#define AIGIS_ENC_NAMESPACE(s) pqmagic_aigis_enc_3_std_##s
#elif (PARAMS == 4)
#define CRYPTO_ALGNAME "Aigis-enc-4"
#define AIGIS_ENC_NAMESPACE(s) pqmagic_aigis_enc_4_std_##s
#else
#error "PARAMS must be in {1,2,3,4}"
#endif

#endif
