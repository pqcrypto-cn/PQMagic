#ifndef PQMAGIC_API_H
#define PQMAGIC_API_H

#include <stddef.h>
#include <stdint.h>

/*
    ML-DSA API START
*/

#define ML_DSA_44_PUBLICKEYBYTES 1312
#define ML_DSA_44_SECRETKEYBYTES 2560
#define ML_DSA_44_SIGBYTES 2420

// return 0 if success, or return error code (neg number).
int pqmagic_ml_dsa_44_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_ml_dsa_44_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

// return 0 if success, or return error code (neg number).
int pqmagic_ml_dsa_44_std_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_ml_dsa_44_std_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    unsigned char *sign_coins, const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
int pqmagic_ml_dsa_44_std_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_ml_dsa_44_std_verify_internal(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_ml_dsa_44_std(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);
// return 0 if verification success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_ml_dsa_44_std_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

#define ML_DSA_65_PUBLICKEYBYTES 1952
#define ML_DSA_65_SECRETKEYBYTES 4032
#define ML_DSA_65_SIGBYTES 3309

// return 0 if success, or return error code (neg number).
int pqmagic_ml_dsa_65_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_ml_dsa_65_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

// return 0 if success, or return error code (neg number).
int pqmagic_ml_dsa_65_std_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_ml_dsa_65_std_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    unsigned char *sign_coins, const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
int pqmagic_ml_dsa_65_std_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_ml_dsa_65_std_verify_internal(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_ml_dsa_65_std(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);
// return 0 if verification success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_ml_dsa_65_std_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

#define ML_DSA_87_PUBLICKEYBYTES 2592
#define ML_DSA_87_SECRETKEYBYTES 4896
#define ML_DSA_87_SIGBYTES 4627

// return 0 if success, or return error code (neg number).
int pqmagic_ml_dsa_87_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_ml_dsa_87_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

// return 0 if success, or return error code (neg number).
int pqmagic_ml_dsa_87_std_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_ml_dsa_87_std_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    unsigned char *sign_coins, const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
int pqmagic_ml_dsa_87_std_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_ml_dsa_87_std_verify_internal(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_ml_dsa_87_std(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);
// return 0 if verification success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_ml_dsa_87_std_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

/*
    ML-DSA API END
*/

/*
    SLH-DSA API START
    ALL USE SIMPLE THASH ACCORDING TO FIPS 205
*/

// ******************* SHA2 ****************** //

#define SLH_DSA_SHA2_128f_PUBLICKEYBYTES 32
#define SLH_DSA_SHA2_128f_SECRETKEYBYTES 64
#define SLH_DSA_SHA2_128f_SIGBYTES 17088

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                     const unsigned char *m, size_t mlen,
                                                     const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_128f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                              const unsigned char *m, size_t mlen,
                                              const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_128f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                   const unsigned char *sm, size_t smlen,
                                                   const unsigned char *pk);

#define SLH_DSA_SHA2_128s_PUBLICKEYBYTES 32
#define SLH_DSA_SHA2_128s_SECRETKEYBYTES 64
#define SLH_DSA_SHA2_128s_SIGBYTES 7856

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                     const unsigned char *m, size_t mlen,
                                                     const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_128s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                              const unsigned char *m, size_t mlen,
                                              const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_128s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                   const unsigned char *sm, size_t smlen,
                                                   const unsigned char *pk);

#define SLH_DSA_SHA2_192f_PUBLICKEYBYTES 48
#define SLH_DSA_SHA2_192f_SECRETKEYBYTES 96
#define SLH_DSA_SHA2_192f_SIGBYTES 35664

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_192f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_192f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                     const unsigned char *m, size_t mlen,
                                                     const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_192f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                              const unsigned char *m, size_t mlen,
                                              const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_192f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                   const unsigned char *sm, size_t smlen,
                                                   const unsigned char *pk);

#define SLH_DSA_SHA2_192s_PUBLICKEYBYTES 48
#define SLH_DSA_SHA2_192s_SECRETKEYBYTES 96
#define SLH_DSA_SHA2_192s_SIGBYTES 16224

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_192s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_192s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                     const unsigned char *m, size_t mlen,
                                                     const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_192s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                              const unsigned char *m, size_t mlen,
                                              const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_192s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                   const unsigned char *sm, size_t smlen,
                                                   const unsigned char *pk);

#define SLH_DSA_SHA2_256f_PUBLICKEYBYTES 64
#define SLH_DSA_SHA2_256f_SECRETKEYBYTES 128
#define SLH_DSA_SHA2_256f_SIGBYTES 49856

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_256f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_256f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                     const unsigned char *m, size_t mlen,
                                                     const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_256f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                              const unsigned char *m, size_t mlen,
                                              const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_256f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                   const unsigned char *sm, size_t smlen,
                                                   const unsigned char *pk);

#define SLH_DSA_SHA2_256s_PUBLICKEYBYTES 64
#define SLH_DSA_SHA2_256s_SECRETKEYBYTES 128
#define SLH_DSA_SHA2_256s_SIGBYTES 29792

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_256s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sha2_256s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                     const unsigned char *m, size_t mlen,
                                                     const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_256s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                              const unsigned char *m, size_t mlen,
                                              const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sha2_256s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                   const unsigned char *sm, size_t smlen,
                                                   const unsigned char *pk);

// ******************* SHA2 ****************** //

// ******************* SHAKE ****************** //

#define SLH_DSA_SHAKE_128f_PUBLICKEYBYTES 32
#define SLH_DSA_SHAKE_128f_SECRETKEYBYTES 64
#define SLH_DSA_SHAKE_128f_SIGBYTES 17088

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                         const unsigned char *m, size_t mlen,
                                                         const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                      const unsigned char *m, size_t mlen,
                                                      const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_128f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                               const unsigned char *m, size_t mlen,
                                               const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_128f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                    const unsigned char *sm, size_t smlen,
                                                    const unsigned char *pk);

#define SLH_DSA_SHAKE_128s_PUBLICKEYBYTES 32
#define SLH_DSA_SHAKE_128s_SECRETKEYBYTES 64
#define SLH_DSA_SHAKE_128s_SIGBYTES 7856

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                         const unsigned char *m, size_t mlen,
                                                         const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                      const unsigned char *m, size_t mlen,
                                                      const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_128s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                               const unsigned char *m, size_t mlen,
                                               const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_128s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                    const unsigned char *sm, size_t smlen,
                                                    const unsigned char *pk);

#define SLH_DSA_SHAKE_192f_PUBLICKEYBYTES 48
#define SLH_DSA_SHAKE_192f_SECRETKEYBYTES 96
#define SLH_DSA_SHAKE_192f_SIGBYTES 35664

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                         const unsigned char *m, size_t mlen,
                                                         const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                      const unsigned char *m, size_t mlen,
                                                      const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_192f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                               const unsigned char *m, size_t mlen,
                                               const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_192f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                    const unsigned char *sm, size_t smlen,
                                                    const unsigned char *pk);

#define SLH_DSA_SHAKE_192s_PUBLICKEYBYTES 48
#define SLH_DSA_SHAKE_192s_SECRETKEYBYTES 96
#define SLH_DSA_SHAKE_192s_SIGBYTES 16224

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_192s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                         const unsigned char *m, size_t mlen,
                                                         const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_192s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                      const unsigned char *m, size_t mlen,
                                                      const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_192s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                               const unsigned char *m, size_t mlen,
                                               const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_192s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                    const unsigned char *sm, size_t smlen,
                                                    const unsigned char *pk);

#define SLH_DSA_SHAKE_256f_PUBLICKEYBYTES 64
#define SLH_DSA_SHAKE_256f_SECRETKEYBYTES 128
#define SLH_DSA_SHAKE_256f_SIGBYTES 49856

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_256f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                         const unsigned char *m, size_t mlen,
                                                         const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_256f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                      const unsigned char *m, size_t mlen,
                                                      const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_256f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                               const unsigned char *m, size_t mlen,
                                               const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_256f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                    const unsigned char *sm, size_t smlen,
                                                    const unsigned char *pk);

#define SLH_DSA_SHAKE_256s_PUBLICKEYBYTES 64
#define SLH_DSA_SHAKE_256s_SECRETKEYBYTES 128
#define SLH_DSA_SHAKE_256s_SIGBYTES 29792

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_256s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                         const unsigned char *m, size_t mlen,
                                                         const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_shake_256s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                      const unsigned char *m, size_t mlen,
                                                      const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_256s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                               const unsigned char *m, size_t mlen,
                                               const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_shake_256s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                    const unsigned char *sm, size_t smlen,
                                                    const unsigned char *pk);

// ******************* SHAKE ****************** //

// ******************* SM3 ****************** //

#define SLH_DSA_SM3_128f_PUBLICKEYBYTES 32
#define SLH_DSA_SM3_128f_SECRETKEYBYTES 64
#define SLH_DSA_SM3_128f_SIGBYTES 17088

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sm3_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                       const unsigned char *m, size_t mlen,
                                                       const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sm3_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                    const unsigned char *m, size_t mlen,
                                                    const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sm3_128f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                             const unsigned char *m, size_t mlen,
                                             const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sm3_128f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                  const unsigned char *sm, size_t smlen,
                                                  const unsigned char *pk);

#define SLH_DSA_SM3_128s_PUBLICKEYBYTES 32
#define SLH_DSA_SM3_128s_SECRETKEYBYTES 64
#define SLH_DSA_SM3_128s_SIGBYTES 7856

// return 0 if success, or return error code (neg number).
int pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sm3_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                       const unsigned char *m, size_t mlen,
                                                       const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_slh_dsa_sm3_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                    const unsigned char *m, size_t mlen,
                                                    const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sm3_128s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                             const unsigned char *m, size_t mlen,
                                             const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_slh_dsa_sm3_128s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                  const unsigned char *sm, size_t smlen,
                                                  const unsigned char *pk);

// ******************* SM3 ****************** //

/*
    SLH-DSA API END
*/

/*
    AIGIS_SIG API START
*/

#define AIGIS_SIG1_PUBLICKEYBYTES 1056
#define AIGIS_SIG1_SECRETKEYBYTES 2448
#define AIGIS_SIG1_SIGBYTES 1852

// return 0 if success, or return error code (neg number).
int pqmagic_aigis_sig1_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_sig1_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

// return 0 if success, or return error code (neg number).
int pqmagic_aigis_sig1_std_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_sig1_std_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
int pqmagic_aigis_sig1_std_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_aigis_sig1_std_verify_internal(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_aigis_sig1_std(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_aigis_sig1_std_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

#define AIGIS_SIG2_PUBLICKEYBYTES 1312
#define AIGIS_SIG2_SECRETKEYBYTES 3376
#define AIGIS_SIG2_SIGBYTES 2445

// return 0 if success, or return error code (neg number).
int pqmagic_aigis_sig2_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_sig2_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

// return 0 if success, or return error code (neg number).
int pqmagic_aigis_sig2_std_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_sig2_std_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
int pqmagic_aigis_sig2_std_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_aigis_sig2_std_verify_internal(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_aigis_sig2_std(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_aigis_sig2_std_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

#define AIGIS_SIG3_PUBLICKEYBYTES 1568
#define AIGIS_SIG3_SECRETKEYBYTES 3888
#define AIGIS_SIG3_SIGBYTES 3046

// return 0 if success, or return error code (neg number).
int pqmagic_aigis_sig3_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_sig3_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

// return 0 if success, or return error code (neg number).
int pqmagic_aigis_sig3_std_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_sig3_std_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
int pqmagic_aigis_sig3_std_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_aigis_sig3_std_verify_internal(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_aigis_sig3_std(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_aigis_sig3_std_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

/*
    AIGIS_SIG API END
*/

/*
    DILITHIUM API START
*/

#define DILITHIUM2_PUBLICKEYBYTES 1312
#define DILITHIUM2_SECRETKEYBYTES 2528
#define DILITHIUM2_SIGBYTES 2420

// return 0 if success, or return error code (neg number).
int pqmagic_dilithium2_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_dilithium2_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

// return 0 if success, or return error code (neg number).
int pqmagic_dilithium2_std_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_dilithium2_std_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    unsigned char *sign_coins, const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
int pqmagic_dilithium2_std_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_dilithium2_std(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);
// return 0 if verification success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_dilithium2_std_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *pk);

#define DILITHIUM3_PUBLICKEYBYTES 1952
#define DILITHIUM3_SECRETKEYBYTES 4000
#define DILITHIUM3_SIGBYTES 3293

// return 0 if success, or return error code (neg number).
int pqmagic_dilithium3_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_dilithium3_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

// return 0 if success, or return error code (neg number).
int pqmagic_dilithium3_std_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_dilithium3_std_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    unsigned char *sign_coins, const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
int pqmagic_dilithium3_std_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_dilithium3_std(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);
// return 0 if verification success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_dilithium3_std_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *pk);

#define DILITHIUM5_PUBLICKEYBYTES 2592
#define DILITHIUM5_SECRETKEYBYTES 4864
#define DILITHIUM5_SIGBYTES 4595

// return 0 if success, or return error code (neg number).
int pqmagic_dilithium5_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_dilithium5_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

// return 0 if success, or return error code (neg number).
int pqmagic_dilithium5_std_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_dilithium5_std_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    unsigned char *sign_coins, const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
int pqmagic_dilithium5_std_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_dilithium5_std(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);
// return 0 if verification success, or return error code (neg number).
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_dilithium5_std_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *pk);

/*
    DILITHIUM API END
*/

/*
    SPHINCS-Alpha API START
    ALL USE SIMPLE THASH.
*/

// ******************* SHA2 ****************** //

#define SPHINCS_A_SHA2_128f_PUBLICKEYBYTES 32
#define SPHINCS_A_SHA2_128f_SECRETKEYBYTES 64
#define SPHINCS_A_SHA2_128f_SIGBYTES 16720

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                          const unsigned char *m, size_t mlen,
                                                          const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                       const unsigned char *m, size_t mlen,
                                                       const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_128f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                const unsigned char *m, size_t mlen,
                                                const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_128f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                     const unsigned char *sm, size_t smlen,
                                                     const unsigned char *pk);

#define SPHINCS_A_SHA2_128s_PUBLICKEYBYTES 32
#define SPHINCS_A_SHA2_128s_SECRETKEYBYTES 64
#define SPHINCS_A_SHA2_128s_SIGBYTES 6880

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                          const unsigned char *m, size_t mlen,
                                                          const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                       const unsigned char *m, size_t mlen,
                                                       const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_128s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                const unsigned char *m, size_t mlen,
                                                const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_128s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                     const unsigned char *sm, size_t smlen,
                                                     const unsigned char *pk);

#define SPHINCS_A_SHA2_192f_PUBLICKEYBYTES 48
#define SPHINCS_A_SHA2_192f_SECRETKEYBYTES 96
#define SPHINCS_A_SHA2_192f_SIGBYTES 34896

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_192f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                          const unsigned char *m, size_t mlen,
                                                          const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_192f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                       const unsigned char *m, size_t mlen,
                                                       const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_192f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                const unsigned char *m, size_t mlen,
                                                const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_192f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                     const unsigned char *sm, size_t smlen,
                                                     const unsigned char *pk);

#define SPHINCS_A_SHA2_192s_PUBLICKEYBYTES 48
#define SPHINCS_A_SHA2_192s_SECRETKEYBYTES 96
#define SPHINCS_A_SHA2_192s_SIGBYTES 14568

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_192s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                          const unsigned char *m, size_t mlen,
                                                          const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_192s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                       const unsigned char *m, size_t mlen,
                                                       const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_192s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                const unsigned char *m, size_t mlen,
                                                const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_192s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                     const unsigned char *sm, size_t smlen,
                                                     const unsigned char *pk);

#define SPHINCS_A_SHA2_256f_PUBLICKEYBYTES 64
#define SPHINCS_A_SHA2_256f_SECRETKEYBYTES 128
#define SPHINCS_A_SHA2_256f_SIGBYTES 49312

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_256f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                          const unsigned char *m, size_t mlen,
                                                          const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_256f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                       const unsigned char *m, size_t mlen,
                                                       const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_256f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                const unsigned char *m, size_t mlen,
                                                const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_256f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                     const unsigned char *sm, size_t smlen,
                                                     const unsigned char *pk);

#define SPHINCS_A_SHA2_256s_PUBLICKEYBYTES 64
#define SPHINCS_A_SHA2_256s_SECRETKEYBYTES 128
#define SPHINCS_A_SHA2_256s_SIGBYTES 27232

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_256s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                          const unsigned char *m, size_t mlen,
                                                          const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sha2_256s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                       const unsigned char *m, size_t mlen,
                                                       const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_256s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                const unsigned char *m, size_t mlen,
                                                const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sha2_256s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                     const unsigned char *sm, size_t smlen,
                                                     const unsigned char *pk);

// ******************* SHA2 ****************** //

// ******************* SHAKE ****************** //

#define SPHINCS_A_SHAKE_128f_PUBLICKEYBYTES 32
#define SPHINCS_A_SHAKE_128f_SECRETKEYBYTES 64
#define SPHINCS_A_SHAKE_128f_SIGBYTES 16720

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                           const unsigned char *m, size_t mlen,
                                                           const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_128f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                 const unsigned char *m, size_t mlen,
                                                 const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_128f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                      const unsigned char *sm, size_t smlen,
                                                      const unsigned char *pk);

#define SPHINCS_A_SHAKE_128s_PUBLICKEYBYTES 32
#define SPHINCS_A_SHAKE_128s_SECRETKEYBYTES 64
#define SPHINCS_A_SHAKE_128s_SIGBYTES 6880

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                           const unsigned char *m, size_t mlen,
                                                           const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_128s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                 const unsigned char *m, size_t mlen,
                                                 const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_128s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                      const unsigned char *sm, size_t smlen,
                                                      const unsigned char *pk);

#define SPHINCS_A_SHAKE_192f_PUBLICKEYBYTES 48
#define SPHINCS_A_SHAKE_192f_SECRETKEYBYTES 96
#define SPHINCS_A_SHAKE_192f_SIGBYTES 34896

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_192f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                           const unsigned char *m, size_t mlen,
                                                           const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_192f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_192f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                 const unsigned char *m, size_t mlen,
                                                 const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_192f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                      const unsigned char *sm, size_t smlen,
                                                      const unsigned char *pk);

#define SPHINCS_A_SHAKE_192s_PUBLICKEYBYTES 48
#define SPHINCS_A_SHAKE_192s_SECRETKEYBYTES 96
#define SPHINCS_A_SHAKE_192s_SIGBYTES 14568

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_192s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                           const unsigned char *m, size_t mlen,
                                                           const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_192s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_192s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                 const unsigned char *m, size_t mlen,
                                                 const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_192s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                      const unsigned char *sm, size_t smlen,
                                                      const unsigned char *pk);

#define SPHINCS_A_SHAKE_256f_PUBLICKEYBYTES 64
#define SPHINCS_A_SHAKE_256f_SECRETKEYBYTES 128
#define SPHINCS_A_SHAKE_256f_SIGBYTES 49312

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_256f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                           const unsigned char *m, size_t mlen,
                                                           const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_256f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_256f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                 const unsigned char *m, size_t mlen,
                                                 const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_256f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                      const unsigned char *sm, size_t smlen,
                                                      const unsigned char *pk);

#define SPHINCS_A_SHAKE_256s_PUBLICKEYBYTES 64
#define SPHINCS_A_SHAKE_256s_SECRETKEYBYTES 128
#define SPHINCS_A_SHAKE_256s_SIGBYTES 27232

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_256s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                           const unsigned char *m, size_t mlen,
                                                           const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_shake_256s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                        const unsigned char *m, size_t mlen,
                                                        const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_256s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                                 const unsigned char *m, size_t mlen,
                                                 const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_shake_256s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                      const unsigned char *sm, size_t smlen,
                                                      const unsigned char *pk);

// ******************* SHAKE ****************** //

// ******************* SM3 ****************** //

#define SPHINCS_A_SM3_128f_PUBLICKEYBYTES 32
#define SPHINCS_A_SM3_128f_SECRETKEYBYTES 64
#define SPHINCS_A_SM3_128f_SIGBYTES 16720

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sm3_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                         const unsigned char *m, size_t mlen,
                                                         const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sm3_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                      const unsigned char *m, size_t mlen,
                                                      const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sm3_128f_simple_std_sign(unsigned char *sm, size_t *smlen,
                                               const unsigned char *m, size_t mlen,
                                               const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sm3_128f_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                    const unsigned char *sm, size_t smlen,
                                                    const unsigned char *pk);

#define SPHINCS_A_SM3_128s_PUBLICKEYBYTES 32
#define SPHINCS_A_SM3_128s_SECRETKEYBYTES 64
#define SPHINCS_A_SM3_128s_SIGBYTES 6880

// return 0 if success, or return error code (neg number).
int pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sm3_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen,
                                                         const unsigned char *m, size_t mlen,
                                                         const unsigned char *sk);
// return 0/1 if verification failed/success, or return error code (neg number).
// sm pointer to output signature (of length CRYPTO_BYTES)
int pqmagic_sphincs_a_sm3_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen,
                                                      const unsigned char *m, size_t mlen,
                                                      const unsigned char *pk);

// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sm3_128s_simple_std_sign(unsigned char *sm, size_t *smlen,
                                               const unsigned char *m, size_t mlen,
                                               const unsigned char *sk);
// sm pointer to output signed message
// (allocated array with signature (CRYPTO_BYTES) + message (mlen bytes))
int pqmagic_sphincs_a_sm3_128s_simple_std_sign_open(unsigned char *m, size_t *mlen,
                                                    const unsigned char *sm, size_t smlen,
                                                    const unsigned char *pk);

// ******************* SM3 ****************** //

/*
    SPHINCS-Alpha API END
*/

///////////////////////////////////////////////////////////////////////////////

/*
    ML-KEM API START
*/

#define ML_KEM_512_PUBLICKEYBYTES 800
#define ML_KEM_512_SECRETKEYBYTES 1632
#define ML_KEM_512_CIPHERTEXTBYTES 768
#define ML_KEM_512_SSBYTES 32

int pqmagic_ml_kem_512_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_ml_kem_512_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_ml_kem_512_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_ml_kem_512_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_ml_kem_512_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

#define ML_KEM_768_PUBLICKEYBYTES 1184
#define ML_KEM_768_SECRETKEYBYTES 2400
#define ML_KEM_768_CIPHERTEXTBYTES 1088
#define ML_KEM_768_SSBYTES 32

int pqmagic_ml_kem_768_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_ml_kem_768_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_ml_kem_768_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_ml_kem_768_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_ml_kem_768_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

#define ML_KEM_1024_PUBLICKEYBYTES 1568
#define ML_KEM_1024_SECRETKEYBYTES 3168
#define ML_KEM_1024_CIPHERTEXTBYTES 1568
#define ML_KEM_1024_SSBYTES 32

int pqmagic_ml_kem_1024_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_ml_kem_1024_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_ml_kem_1024_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_ml_kem_1024_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_ml_kem_1024_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

/*
    ML-KEM API END
*/

/*
    KYBER API START
*/

#define KYBER512_PUBLICKEYBYTES 800
#define KYBER512_SECRETKEYBYTES 1632
#define KYBER512_CIPHERTEXTBYTES 768
#define KYBER512_SSBYTES 32

int pqmagic_kyber512_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_kyber512_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_kyber512_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_kyber512_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_kyber512_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

#define KYBER768_PUBLICKEYBYTES 1184
#define KYBER768_SECRETKEYBYTES 2400
#define KYBER768_CIPHERTEXTBYTES 1088
#define KYBER768_SSBYTES 32

int pqmagic_kyber768_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_kyber768_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_kyber768_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_kyber768_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_kyber768_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

#define KYBER1024_PUBLICKEYBYTES 1568
#define KYBER1024_SECRETKEYBYTES 3168
#define KYBER1024_CIPHERTEXTBYTES 1568
#define KYBER1024_SSBYTES 32

int pqmagic_kyber1024_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_kyber1024_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_kyber1024_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_kyber1024_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_kyber1024_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

/*
    KYBER API END
*/

/*
    AIGIS-ENC API START
*/

#define AIGIS_ENC_1_PUBLICKEYBYTES 672
#define AIGIS_ENC_1_SECRETKEYBYTES 1568
#define AIGIS_ENC_1_CIPHERTEXTBYTES 736
#define AIGIS_ENC_1_SSBYTES 32

int pqmagic_aigis_enc_1_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_enc_1_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_aigis_enc_1_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_aigis_enc_1_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_aigis_enc_1_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

#define AIGIS_ENC_2_PUBLICKEYBYTES 896
#define AIGIS_ENC_2_SECRETKEYBYTES 2208
#define AIGIS_ENC_2_CIPHERTEXTBYTES 992
#define AIGIS_ENC_2_SSBYTES 32

int pqmagic_aigis_enc_2_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_enc_2_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_aigis_enc_2_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_aigis_enc_2_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_aigis_enc_2_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

#define AIGIS_ENC_3_PUBLICKEYBYTES 992
#define AIGIS_ENC_3_SECRETKEYBYTES 2304
#define AIGIS_ENC_3_CIPHERTEXTBYTES 1056
#define AIGIS_ENC_3_SSBYTES 32

int pqmagic_aigis_enc_3_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_enc_3_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_aigis_enc_3_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_aigis_enc_3_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_aigis_enc_3_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

#define AIGIS_ENC_4_PUBLICKEYBYTES 1440
#define AIGIS_ENC_4_SECRETKEYBYTES 3168
#define AIGIS_ENC_4_CIPHERTEXTBYTES 1568
#define AIGIS_ENC_4_SSBYTES 32

int pqmagic_aigis_enc_4_std_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Internal Method
 */
int pqmagic_aigis_enc_4_std_keypair_internal(
    unsigned char *pk, unsigned char *sk,
    unsigned char *keypair_coins);

int pqmagic_aigis_enc_4_std_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk);

/*
 * Internal Method
 */
int pqmagic_aigis_enc_4_std_enc_internal(
    unsigned char *ct, unsigned char *ss,
    const unsigned char *pk, unsigned char *kem_enc_coins);

int pqmagic_aigis_enc_4_std_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

/*
    AIGIS-ENC API END
*/

#endif
