#include <string.h>
#include "api.h"
#include "params.h"
#include "verify.h"
#include "owcpa.h"
#include "hashkdf.h"
#include "pqmagic_config.h"
#include "utils/randombytes.h"


PQMAGIC_EXPORT int crypto_kem_keypair_internal(
  unsigned char *pk, 
  unsigned char *sk,
  const unsigned char *coins)
{
  size_t i;
  owcpa_keypair(pk, sk, coins);
  for(i=0;i<PK_BYTES;i++)
    sk[POLYVEC_BYTES + i] = pk[i];
  Hash(sk+SK_BYTES-2*SEED_BYTES,pk,PK_BYTES); 
  memcpy(sk + SK_BYTES - SEED_BYTES, coins+SEED_BYTES, SEED_BYTES);/* Value z for implicit reject */
  return 0;
}

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure ML-KEM key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key
*                (an already allocated array of ML_KEM_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key
*                (an already allocated array of ML_KEM_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
  unsigned char coins[2*SEED_BYTES];
  randombytes(coins, 2*SEED_BYTES);
  return crypto_kem_keypair_internal(pk, sk, coins);
}

PQMAGIC_EXPORT int crypto_kem_enc_internal(
  unsigned char *ct, 
  unsigned char *ss, 
  const unsigned char *pk,
  const unsigned char *coins)
{
  unsigned char  kr[SEED_BYTES];                                        /* Will contain key, coins */
  unsigned char buf[3*SEED_BYTES];                          

  // randombytes(buf, SEED_BYTES);
  memcpy(buf, coins, SEED_BYTES);

  Hash(buf,buf,SEED_BYTES);                                           /* Don't release system RNG output */

  Hash(buf + SEED_BYTES, pk, PK_BYTES);                               /* Multitarget countermeasure for coins + contributory KEM */

  Hash(kr, buf, 2*SEED_BYTES);

  owcpa_enc(ct, buf, pk, kr);                                         /* encrypt the pre-k using kr */

  Hash(buf+2*SEED_BYTES, ct, CT_BYTES);                               /* overwrite coins in kr with H(c) */

  Hash(ss, buf, 3*SEED_BYTES);                                        /* hash concatenation of pre-k and H(c) to k */
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct: pointer to output cipher text
*                (an already allocated array of ML_KEM_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of ML_KEM_SSBYTES bytes)
*              - const unsigned char *pk: pointer to input public key
*                (an already allocated array of ML_KEM_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk)
{
  unsigned char coins[SEED_BYTES];
  randombytes(coins, SEED_BYTES);
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
PQMAGIC_EXPORT int crypto_kem_dec(
  unsigned char *ss, 
  const unsigned char *ct, 
  const unsigned char *sk)
{
  size_t i; 
  int fail;
  unsigned char cmp[CT_BYTES];
  unsigned char buf[3*SEED_BYTES];
  unsigned char kr[SEED_BYTES];                                         /* Will contain key, coins, qrom-hash */
  const unsigned char *pk = sk + POLYVEC_BYTES;

  owcpa_dec(buf, ct, sk);                                               /*obtaining pre-k*/
                                                                              
  for(i=0;i<SEED_BYTES;i++)                                             /* Multitarget countermeasure for coins + contributory KEM */
    buf[SEED_BYTES+i] = sk[SK_BYTES-2*SEED_BYTES+i];                    /* Save hash by storing H(pk) in sk */

  Hash(kr, buf, 2*SEED_BYTES);
  owcpa_enc(cmp, buf, pk, kr);                                          /* coins are in kr+SEED_BYTES */

  fail = verify(ct, cmp, CT_BYTES);

  Hash(buf+2*SEED_BYTES, ct, CT_BYTES);                                 /* overwrite coins in kr with H(c)  */

  cmov(buf, sk+SK_BYTES-SEED_BYTES, SEED_BYTES, fail);                  /* Overwrite pre-k with z on re-encryption failure */

  Hash(ss, buf, 3*SEED_BYTES);    
  
  return 0;
}
