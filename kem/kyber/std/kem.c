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
*              - unsigned char *coins: pointer to random message
*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_kem_keypair_internal(
  unsigned char *pk, 
  unsigned char *sk,
  const unsigned char *coins)
{
  indcpa_keypair(pk, sk, coins);
  memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, coins+KYBER_SYMBYTES, KYBER_SYMBYTES);
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
  unsigned char coins[2*KYBER_SYMBYTES];
  randombytes(coins, 2*KYBER_SYMBYTES);
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
PQMAGIC_EXPORT int crypto_kem_enc_internal(
  unsigned char *ct,
  unsigned char *ss,
  const unsigned char *pk,
  const unsigned char *coins)
{

  unsigned char buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  unsigned char kr[2*KYBER_SYMBYTES];

  // randombytes(buf, KYBER_SYMBYTES);
  memcpy(buf, coins, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
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
  unsigned char coins[KYBER_SYMBYTES];
  randombytes(coins, KYBER_SYMBYTES);
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
  unsigned char buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  unsigned char kr[2*KYBER_SYMBYTES];
  unsigned char cmp[KYBER_CIPHERTEXTBYTES];
  const unsigned char *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  memcpy(buf+KYBER_SYMBYTES, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}
