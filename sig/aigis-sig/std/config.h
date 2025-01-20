#ifndef CONFIG_H
#define CONFIG_H

#ifndef AIGIS_SIG_MODE
#define AIGIS_SIG_MODE 2
#endif

#define PARAMS AIGIS_SIG_MODE

#if PARAMS == 1
#define CRYPTO_ALGNAME "Aigis_sig1"
#define AIGIS_SIG_NAMESPACETOP pqmagic_aigis_sig1_std
#define AIGIS_SIG_NAMESPACE(s) pqmagic_aigis_sig1_std_##s
#elif PARAMS == 2
#define CRYPTO_ALGNAME "Aigis_sig2"
#define AIGIS_SIG_NAMESPACETOP pqmagic_aigis_sig2_std
#define AIGIS_SIG_NAMESPACE(s) pqmagic_aigis_sig2_std_##s
#elif PARAMS == 3
#define CRYPTO_ALGNAME "Aigis_sig3"
#define AIGIS_SIG_NAMESPACETOP pqmagic_aigis_sig3_std
#define AIGIS_SIG_NAMESPACE(s) pqmagic_aigis_sig3_std_##s
#endif

#endif
