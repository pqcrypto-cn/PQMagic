#ifndef CONFIG_H
#define CONFIG_H


#ifndef DILITHIUM_MODE
#define DILITHIUM_MODE 2
#endif

#if DILITHIUM_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2"
#define DILITHIUM_NAMESPACETOP pqmagic_dilithium2_std
#define DILITHIUM_NAMESPACE(s) pqmagic_dilithium2_std_##s
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define DILITHIUM_NAMESPACETOP pqmagic_dilithium3_std
#define DILITHIUM_NAMESPACE(s) pqmagic_dilithium3_std_##s
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define DILITHIUM_NAMESPACETOP pqmagic_dilithium5_std
#define DILITHIUM_NAMESPACE(s) pqmagic_dilithium5_std_##s
#endif
#endif
