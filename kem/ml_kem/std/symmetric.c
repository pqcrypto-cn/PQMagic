#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "symmetric.h"

#ifdef USE_SHAKE
/*************************************************
* Name:        shake128_absorb_extend
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to ML_KEM_SYMBYTES input to be absorbed into state
*              - uint8_t i: additional byte of input
*              - uint8_t j: additional byte of input
**************************************************/
void shake128_absorb_extend(keccak_state *state,
                           const uint8_t seed[ML_KEM_SYMBYTES],
                           uint8_t x,
                           uint8_t y)
{
  uint8_t extseed[ML_KEM_SYMBYTES+2];

  memcpy(extseed, seed, ML_KEM_SYMBYTES);
  extseed[ML_KEM_SYMBYTES+0] = x;
  extseed[ML_KEM_SYMBYTES+1] = y;

  shake128_absorb_once(state, extseed, sizeof(extseed));
}

/*************************************************
* Name:        shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length ML_KEM_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[ML_KEM_SYMBYTES], uint8_t nonce)
{
  uint8_t extkey[ML_KEM_SYMBYTES+1];

  memcpy(extkey, key, ML_KEM_SYMBYTES);
  extkey[ML_KEM_SYMBYTES] = nonce;

  shake256(out, outlen, extkey, sizeof(extkey));
}

/*************************************************
* Name:        shake256_rkprf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - const uint8_t *key: pointer to the key (of length ML_KEM_SYMBYTES)
*              - uint8_t ct: ciphertext
**************************************************/
void shake256_rkprf(uint8_t out[ML_KEM_SSBYTES], const uint8_t key[ML_KEM_SYMBYTES], const uint8_t ct[ML_KEM_CIPHERTEXTBYTES])
{
  keccak_state s;

  shake256_init(&s);
  shake256_absorb(&s, key, ML_KEM_SYMBYTES);
  shake256_absorb(&s, ct, ML_KEM_CIPHERTEXTBYTES);
  shake256_finalize(&s);
  shake256_squeeze(out, ML_KEM_SSBYTES, &s);
}

#else

/*************************************************
* Name:        sm3_prf
*
* Description: Usage of SM3 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SM3 output
*
* Arguments:   - uint8_t *out:       pointer to output
*              - size_t outlen:      number of requested output bytes
*              - const uint8_t *key: pointer to the key
*                                    (of length ML_KEM_SYMBYTES)
*              - uint8_t nonce:      single-byte nonce (public PRF input)
**************************************************/
void sm3_prf(uint8_t *out,
             size_t outlen,
             const uint8_t key[ML_KEM_SYMBYTES],
             uint8_t nonce)
{
  uint8_t extkey[ML_KEM_SYMBYTES+1];

  memcpy(extkey, key, ML_KEM_SYMBYTES);
  extkey[ML_KEM_SYMBYTES] = nonce;

  sm3_extended(out, outlen, extkey, sizeof(extkey));
}

/*************************************************
* Name:        sm3_rkprf
*
* Description: Usage of SM3 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SM3 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - const uint8_t *key: pointer to the key (of length ML_KEM_SYMBYTES)
*              - uint8_t ct: ciphertext
**************************************************/
void sm3_rkprf(uint8_t out[ML_KEM_SSBYTES], const uint8_t key[ML_KEM_SYMBYTES], const uint8_t ct[ML_KEM_CIPHERTEXTBYTES])
{
  uint8_t z_ct[ML_KEM_SYMBYTES + ML_KEM_CIPHERTEXTBYTES];
  memcpy(z_ct, key, ML_KEM_SYMBYTES);
  memcpy(z_ct + ML_KEM_SYMBYTES, ct, ML_KEM_CIPHERTEXTBYTES);
  // kdf(out, z_ct, ML_KEM_SYMBYTES + ML_KEM_CIPHERTEXTBYTES);
  sm3_extended(out, ML_KEM_SYMBYTES, z_ct, ML_KEM_SYMBYTES + ML_KEM_CIPHERTEXTBYTES);
}

#endif
