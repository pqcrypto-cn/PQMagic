#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "kem.h"
#include "params.h"
#include "symmetric.h"
#include "verify.h"
#include "indcpa.h"
#include "pqmagic_config.h"
#include "utils/randombytes.h"

/*************************************************
* Name:        crypto_kem_keypair_internal
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*              - const unsigned char *coins: pointer to random message
*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_kem_keypair_internal(unsigned char *pk, 
                                unsigned char *sk,
                                const unsigned char *coins)
{
  indcpa_keypair(pk, sk, coins);
  memcpy(sk+ML_KEM_INDCPA_SECRETKEYBYTES, pk, ML_KEM_INDCPA_PUBLICKEYBYTES);
  hash_h(sk+ML_KEM_SECRETKEYBYTES-2*ML_KEM_SYMBYTES, pk, ML_KEM_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  memcpy(sk+ML_KEM_SECRETKEYBYTES-ML_KEM_SYMBYTES, coins+ML_KEM_SYMBYTES, ML_KEM_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
  unsigned char coins[2*ML_KEM_SYMBYTES];
  randombytes(coins, 2*ML_KEM_SYMBYTES);
  return crypto_kem_keypair_internal(pk, sk, coins);
}


/*************************************************
* Name:        crypto_kem_enc_internal
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct: pointer to output cipher text
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - const unsigned char *coins: pointer to random message
*
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_kem_enc_internal(unsigned char *ct,
                            unsigned char *ss,
                            const unsigned char *pk,
                            const unsigned char *coins)
{

  unsigned char buf[2*ML_KEM_SYMBYTES];
  /* Will contain key, coins */
  unsigned char kr[2*ML_KEM_SYMBYTES];

  memcpy(buf, coins, ML_KEM_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+ML_KEM_SYMBYTES, pk, ML_KEM_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*ML_KEM_SYMBYTES);

  /* coins are in kr+ML_KEM_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+ML_KEM_SYMBYTES);

  memcpy(ss, kr, ML_KEM_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct: pointer to output cipher text
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk)
{

  unsigned char coins[ML_KEM_SYMBYTES];
  randombytes(coins, ML_KEM_SYMBYTES);
  /* Don't release system RNG output */
  return crypto_kem_enc_internal(ct, ss, pk, coins);
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const unsigned char *sk: pointer to input private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
PQMAGIC_EXPORT int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk)
{
  int fail;
  unsigned char buf[2*ML_KEM_SYMBYTES];
  /* Will contain key, coins */
  unsigned char kr[2*ML_KEM_SYMBYTES];
  unsigned char cmp[ML_KEM_CIPHERTEXTBYTES];
  const unsigned char *pk = sk+ML_KEM_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  memcpy(buf+ML_KEM_SYMBYTES, sk+ML_KEM_SECRETKEYBYTES-2*ML_KEM_SYMBYTES, ML_KEM_SYMBYTES);
  hash_g(kr, buf, 2*ML_KEM_SYMBYTES);

  /* coins are in kr+ML_KEM_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+ML_KEM_SYMBYTES);

  fail = verify(ct, cmp, ML_KEM_CIPHERTEXTBYTES);

  /* hash concatenation of z and c to candidate k */
  rkprf(ss, sk+ML_KEM_SECRETKEYBYTES-ML_KEM_SYMBYTES, ct);

  cmov(ss, kr, ML_KEM_SYMBYTES, !fail);

  return 0;
}
