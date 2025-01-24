#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "symmetric.h"
#include "pqmagic_config.h"
#include "utils/randombytes.h"
#ifndef USE_SHAKE
#include "include/sm3_extended.h"
#endif

// #define USE_POLY_PRINT
#ifdef USE_POLY_PRINT
#include "./utils/utils.h"
#endif

/*************************************************
* Name:        crypto_sign_keypair_internal
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*              - const uint8_t *coins: pointer to random message
*                             (of length SEEDBYTES bytes) 
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_sign_keypair_internal(
  uint8_t *pk, 
  uint8_t *sk,
  const uint8_t *coins) 
{
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
  uint8_t tr[TRBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  memcpy(seedbuf, coins, SEEDBYTES);
  seedbuf[SEEDBYTES] = K;
  seedbuf[SEEDBYTES + 1] = L;
#ifdef USE_SHAKE
  shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES+2);
#else
  sm3_extended(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
#endif
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;
  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(&t1, &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
#ifdef USE_SHAKE
  shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
#else
  sm3_extended(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
#endif
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  return 0;
}

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {

  unsigned char coins[SEEDBYTES];
  randombytes(coins, SEEDBYTES);
  return crypto_sign_keypair_internal(pk, sk, coins);
}

/*************************************************
* Name:        crypto_sign_signature_internal
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *coins: pointer to random message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success), -1 (context string too long error)
**************************************************/
PQMAGIC_EXPORT int crypto_sign_signature_internal(
  uint8_t *sig,
  size_t *siglen,
  const uint8_t *m,
  size_t mlen,
  const uint8_t *coins,
  const uint8_t *sk)
{
  unsigned int n;
  uint8_t seedbuf[2*SEEDBYTES + TRBYTES + RNDBYTES + 2*CRHBYTES];
  uint8_t *rho, *tr, *key, *rnd, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
#ifdef USE_SHAKE
  keccak_state state;
#else
  uint8_t *tr_msg = (uint8_t*)malloc(TRBYTES + mlen);
  uint8_t mu_sig[CRHBYTES + K*POLYW1_PACKEDBYTES];
#endif

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + TRBYTES;
  rnd = key + SEEDBYTES;
  mu = rnd + RNDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
#ifdef USE_SHAKE
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  memcpy(rnd, coins, RNDBYTES);
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);
#else
  memcpy(tr_msg, tr, TRBYTES);
  memcpy(tr_msg + TRBYTES, m, mlen);
  sm3_extended(mu, CRHBYTES, tr_msg, TRBYTES + mlen);

  memcpy(rnd, coins, RNDBYTES);
  sm3_extended(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);
#endif

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

#ifdef USE_SHAKE
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, CTILDEBYTES, &state);
#else
  memcpy(mu_sig, mu, CRHBYTES);
  memcpy(mu_sig + CRHBYTES, sig, K*POLYW1_PACKEDBYTES);
  sm3_extended(sig, CTILDEBYTES, mu_sig, CRHBYTES + K*POLYW1_PACKEDBYTES);
#endif
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  /* Write signature */
  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES;
#ifndef USE_SHAKE
  free(tr_msg);
  tr_msg = NULL;
#endif
  return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *ctx:   pointer to ctx string
*              - size_t ctx_len: length of ctx string
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success), -1 (context string too long error)
**************************************************/
PQMAGIC_EXPORT int crypto_sign_signature(
  uint8_t *sig,
  size_t *siglen,
  const uint8_t *m,
  size_t mlen,
  const uint8_t *ctx,
  size_t ctx_len,
  const uint8_t *sk)
{

  if(ctx_len > 255) {
    return -1;
  }

  uint8_t coins[RNDBYTES];
  uint8_t *m_extended = (uint8_t*)malloc(mlen + ctx_len + 2);

#ifdef ML_DSA_RANDOMIZED_SIGNING
  randombytes(coins, RNDBYTES);
#else
  memset(coins, 0, RNDBYTES);
#endif

  m_extended[0] = 0;
  m_extended[1] = (uint8_t)ctx_len;
  memcpy(m_extended + 2, ctx, ctx_len);
  memcpy(m_extended + 2 + ctx_len, m, mlen);

  return crypto_sign_signature_internal(sig, siglen, m_extended, mlen + ctx_len + 2, coins, sk);
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - uint8_t *ctx:   pointer to ctx string
*              - size_t ctx_len: length of ctx string
*              - uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success), -1 (context string too long error)
**************************************************/
PQMAGIC_EXPORT int crypto_sign(
  uint8_t *sm,
  size_t *smlen,
  const uint8_t *m,
  size_t mlen,
  const uint8_t *ctx,
  size_t ctx_len,
  const uint8_t *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  int ret = crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, ctx, ctx_len, sk);
  *smlen += mlen;
  return ret;
}

/*************************************************
* Name:        crypto_sign_verify_internal
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
PQMAGIC_EXPORT int crypto_sign_verify_internal(
  const uint8_t *sig,
  size_t siglen,
  const uint8_t *m,
  size_t mlen,
  const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[K*POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[CTILDEBYTES];
  uint8_t c2[CTILDEBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
#ifdef USE_SHAKE
  keccak_state state;
#else
  uint8_t *tr_msg = (uint8_t*)malloc(TRBYTES + mlen);
  uint8_t mu_buf[CRHBYTES + K*POLYW1_PACKEDBYTES];
#endif

  if(siglen != CRYPTO_BYTES) {
#ifndef USE_SHAKE
    free(tr_msg);
    tr_msg = NULL;
#endif
    return -1;
  }

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(c, &z, &h, sig)) {
#ifndef USE_SHAKE
    free(tr_msg);
    tr_msg = NULL;
#endif
    return -1;
  }

  if(polyvecl_chknorm(&z, GAMMA1 - BETA)) {
#ifndef USE_SHAKE
    free(tr_msg);
    tr_msg = NULL;
#endif
    return -1;
  }

  /* Compute tr = H(rho, t1) = H(pk) */
  /* Compute CRH(tr, msg)            */
#ifdef USE_SHAKE
  shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, TRBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);
#else
  sm3_extended(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  memcpy(tr_msg, mu, TRBYTES);
  memcpy(tr_msg + TRBYTES, m, mlen);
  sm3_extended(mu, CRHBYTES, tr_msg, TRBYTES + mlen);
#endif
  

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
#ifdef USE_SHAKE
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, CTILDEBYTES, &state);
  for(i = 0; i < CTILDEBYTES; ++i)
    if(c[i] != c2[i])
      return -1;
#else
  memcpy(mu_buf, mu, CRHBYTES);
  memcpy(mu_buf + CRHBYTES, buf, K*POLYW1_PACKEDBYTES);
  sm3_extended(c2, CTILDEBYTES, mu_buf, CRHBYTES + K*POLYW1_PACKEDBYTES);

  for(i = 0; i < CTILDEBYTES; ++i)
    if(c[i] != c2[i]) {
      free(tr_msg);
      tr_msg = NULL;
      return -1;
    }
  
  free(tr_msg);
  tr_msg = NULL;
#endif

  return 0;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - uint8_t *ctx:   pointer to ctx string
*              - size_t ctx_len: length of ctx string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
PQMAGIC_EXPORT int crypto_sign_verify(
  const uint8_t *sig,
  size_t siglen,
  const uint8_t *m,
  size_t mlen,
  const uint8_t *ctx,
  size_t ctx_len,
  const uint8_t *pk)
{

  if(ctx_len > 255) {
    return -1;
  }

  uint8_t *m_extended = (uint8_t*)malloc(mlen + ctx_len + 2);

  m_extended[0] = 0;
  m_extended[1] = (uint8_t)ctx_len;
  memcpy(m_extended + 2, ctx, ctx_len);
  memcpy(m_extended + 2 + ctx_len, m, mlen);

  return crypto_sign_verify_internal(sig, siglen, m_extended, mlen + ctx_len + 2, pk);
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - uint8_t *ctx:   pointer to ctx string
*              - size_t ctx_len: length of ctx string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
PQMAGIC_EXPORT int crypto_sign_open(
  uint8_t *m,
  size_t *mlen,
  const uint8_t *sm,
  size_t smlen,
  const uint8_t *ctx,
  size_t ctx_len,
  const uint8_t *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if(crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, ctx, ctx_len, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}
