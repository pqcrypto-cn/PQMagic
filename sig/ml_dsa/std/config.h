#ifndef CONFIG_H
#define CONFIG_H


#ifndef ML_DSA_MODE
#define ML_DSA_MODE 44
#endif

#if ML_DSA_MODE == 44 // Category 2
#define CRYPTO_ALGNAME "ML-DSA-44"
#define ML_DSA_NAMESPACETOP pqmagic_ml_dsa_44_std
#define ML_DSA_NAMESPACE(s) pqmagic_ml_dsa_44_std_##s
#elif ML_DSA_MODE == 65 // Category 3
#define CRYPTO_ALGNAME "ML-DSA-65"
#define ML_DSA_NAMESPACETOP pqmagic_ml_dsa_65_std
#define ML_DSA_NAMESPACE(s) pqmagic_ml_dsa_65_std_##s
#elif ML_DSA_MODE == 87 // Category 5
#define CRYPTO_ALGNAME "ML-DSA-87"
#define ML_DSA_NAMESPACETOP pqmagic_ml_dsa_87_std
#define ML_DSA_NAMESPACE(s) pqmagic_ml_dsa_87_std_##s
#else
#error "ML_DSA_MODE must be in {44,65,87}"
#endif

#endif
