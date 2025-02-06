#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "packing.h"
#include "params.h"
#include "polyvec.h"
#include "poly.h"
#include "sign.h"
#include "pqmagic_config.h"
#include "utils/randombytes.h"
#ifdef USE_SHAKE
#include "hash/keccak/fips202.h"
#else
#include "fips202.h"
#include "include/sm3_extended.h"
#endif

/*generate the public matrix from a seed*/
PQMAGIC_EXPORT void expand_mat(polyvecl mat[PARAM_K], const unsigned char rho[SEEDBYTES]) {
  unsigned int i, j, pos, ctr;
  unsigned char inbuf[SEEDBYTES + 2];
#if QBITS == 21
  unsigned char outbuf[6*SHAKE128_RATE]; /* Probability that we need more than 6 blocks: < 2^{-137}.*/
#elif QBITS == 22
  unsigned char outbuf[7*SHAKE128_RATE]; /* Probability that we need more than 7 blocks: < 2^{-174}.*/
#endif
  uint32_t val;

  for(i = 0; i < SEEDBYTES; ++i)
	  inbuf[i] = rho[i];

  for(i = 0; i < PARAM_K; ++i) {
	  for(j = 0; j < PARAM_L; ++j) {
		  ctr = pos = 0;
		  inbuf[SEEDBYTES] = i + (j << 4);

#ifdef USE_SHAKE
      keccak_state state;
      shake128_absorb_once(&state, inbuf, SEEDBYTES + 1);
      shake128_squeezeblocks(outbuf, 6, &state);
#else
      inbuf[SEEDBYTES + 1] = 0;
      sm3_extended(outbuf, 6*SHAKE128_RATE, inbuf, SEEDBYTES+2);
#endif

#if QBITS == 21 
		  while(ctr < PARAM_N) {
			  val  = outbuf[pos++];
			  val |= (uint32_t)outbuf[pos++] << 8;
			  val |= (uint32_t)outbuf[pos++] << 16;

			  val &= 0x1FFFFF;
			  /* Rejection sampling */
			  if(val < PARAM_Q)
				  mat[i].vec[j].coeffs[ctr++] = val;
		  }

#elif QBITS == 22 
		  /* Probability that we need more than 6 blocks: < 2^{-65}.
		  * Probability that we need more than 7 blocks: < 2^{-174}. */

		  do {
			  val  = outbuf[pos++];
			  val |= (uint32_t)outbuf[pos++] << 8;
			  val |= (uint32_t)outbuf[pos++] << 16;
			  val &= 0x3FFFFF;

			  if(val < PARAM_Q)
				  mat[i].vec[j].coeffs[ctr++] = val;
		  }while(ctr < 225);
		  /* Probability we need more than 6 blocks to generate 225 elements: < 2^{-135}.*/
		  /* Probability we need more than 258 bytes to generate the last 31 elements: < 2^{-133}.*/
		  /// TODO: ??? Goes in this if condition has a huge probability. 
      if(6*SHAKE128_RATE- pos < 258) {
  #ifdef USE_SHAKE
        shake128_squeezeblocks(outbuf + 6 * SHAKE128_RATE, 1, &state);
  #else
        inbuf[SEEDBYTES + 1] = 1;
        sm3_extended(outbuf + 6*SHAKE128_RATE, SHAKE128_RATE, inbuf, SEEDBYTES+2);
  #endif
      }

		  do {
			  val  = outbuf[pos++];
			  val |= (uint32_t)outbuf[pos++] << 8;
			  val |= (uint32_t)outbuf[pos++] << 16;

			  val &= 0x3FFFFF;

			  if(val < PARAM_Q)
				  mat[i].vec[j].coeffs[ctr++] = val;
		  }while(ctr < PARAM_N);
#endif
	  }
  }
}

/*generate the the challenge c*/
PQMAGIC_EXPORT void challenge(poly *c,
               const unsigned char mu[CRHBYTES],
               const polyveck *w1) 
{
  unsigned int i, b, pos;
  unsigned char inbuf[CRHBYTES + PARAM_K*POLW1_SIZE_PACKED];
  unsigned char outbuf[SHAKE256_RATE];
  uint64_t signs, mask;
#ifdef USE_SHAKE
  keccak_state state;
#else
  uint8_t inbuf_ext[CRHBYTES + PARAM_K*POLW1_SIZE_PACKED + 1];
#endif

  for(i = 0; i < CRHBYTES; ++i)
    inbuf[i] = mu[i];
  for(i = 0; i < PARAM_K; ++i)
    polyw1_pack(inbuf + CRHBYTES + i*POLW1_SIZE_PACKED, w1->vec+i);

#ifdef USE_SHAKE
  shake256_absorb_once(&state, inbuf, CRHBYTES + PARAM_K*POLW1_SIZE_PACKED);
  shake256_squeezeblocks(outbuf, 1, &state);
#else
  memcpy(inbuf_ext, inbuf, CRHBYTES + PARAM_K*POLW1_SIZE_PACKED);
  inbuf_ext[CRHBYTES + PARAM_K*POLW1_SIZE_PACKED] = 0;
  sm3_extended(outbuf, SHAKE256_RATE, inbuf_ext, CRHBYTES+PARAM_K*POLW1_SIZE_PACKED+1);
#endif

  signs = 0;
  for(i = 0; i < 8; ++i)
    signs |= (uint64_t)outbuf[i] << 8*i;

  pos = 8;
  mask = 1;

  for(i = 0; i < PARAM_N; ++i)
    c->coeffs[i] = 0;

  for(i = 196; i < 256; ++i) {
    do {
      if(pos >= SHAKE256_RATE) {
#ifdef USE_SHAKE
        shake256_squeezeblocks(outbuf, 1, &state);
#else
        inbuf_ext[CRHBYTES+PARAM_K*POLW1_SIZE_PACKED]++;
        sm3_extended(outbuf, SHAKE256_RATE, inbuf_ext, CRHBYTES+PARAM_K*POLW1_SIZE_PACKED+1);
#endif
        pos = 0;
      }

      b = outbuf[pos++];
    } while(b > i);

    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = (signs & mask) ? PARAM_Q - 1 : 1;
    mask <<= 1;
  }
}

/*************************************************
* Name:        crypto_sign_keypair_internal
*
* Description: Generates public and private key.
*
* Arguments:   - unsigned char *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*              - const unsigned char *coins: pointer to random message
*                             (of length SEEDBYTES bytes) 
* Returns 0 (success)
**************************************************/
/*************************************************
* generate a pair of public key pk and secret key sk, 
* where pk = rho|t1
*       sk = rho|key|hash(pk)|s1|s2|t0
**************************************************/
PQMAGIC_EXPORT int crypto_sign_keypair_internal(
  unsigned char *pk, 
  unsigned char *sk,
  const unsigned char *coins)
{
  unsigned int i;
  unsigned char buf[3*SEEDBYTES + CRHBYTES]; //buf = r|rho|key|hash(pk)
  uint16_t nonce = 0;
  polyvecl mat[PARAM_K];
  polyvecl s1, s1hat;
  polyveck s2, t, t1, t0;
  
  // randombytes(buf, SEEDBYTES);
  // sm3_extended(buf, 3*SEEDBYTES, buf, SEEDBYTES);
#ifdef USE_SHAKE
  shake256(buf, 3*SEEDBYTES, coins, SEEDBYTES);
#else
  sm3_extended(buf, 3*SEEDBYTES, coins, SEEDBYTES); 
#endif
  

  expand_mat(mat, &buf[SEEDBYTES]);

  for(i = 0; i < PARAM_L; ++i)
    poly_uniform_eta1(&s1.vec[i], buf, nonce++);
  for(i = 0; i < PARAM_K; ++i)
    poly_uniform_eta2(&s2.vec[i], buf, nonce++);

  s1hat = s1;
  polyvecl_ntt(&s1hat);
  for(i = 0; i < PARAM_K; ++i) {
    polyvecl_pointwise_acc_invmontgomery(&t.vec[i], mat+i, &s1hat);//output coefficient  <=2*Q
    poly_invntt_montgomery(t.vec+i);//output coefficient  <=2*Q
  }

  polyveck_add(&t, &t, &s2);//output coefficient <=4*Q
  polyveck_freeze4q(&t);
  polyveck_power2round(&t1, &t0, &t);
  pack_pk(pk, &buf[SEEDBYTES], &t1);

#ifdef USE_SHAKE
  shake256(buf + 3*SEEDBYTES, CRHBYTES, pk, AIGIS_SIG_PUBLICKEYBYTES);
#else
  sm3_extended(&buf[3*SEEDBYTES], CRHBYTES, pk, AIGIS_SIG_PUBLICKEYBYTES);
#endif
  pack_sk(sk,&buf[SEEDBYTES], &s1, &s2, &t0);

  return 0;

}

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - unsigned char *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
PQMAGIC_EXPORT int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {

  unsigned char coins[SEEDBYTES];
  randombytes(coins, SEEDBYTES);
  return crypto_sign_keypair_internal(pk, sk, coins);
}

/*************************************************
* Name:        crypto_sign_signature_internal
*
* Description: Computes signature.
*
* Arguments:   - unsigned char *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - unsigned char *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - unsigned char *sk:    pointer to bit-packed secret key
*
* Returns 0 (success), -1 (context string too long error)
**************************************************/
/*************************************************
* create a signature sm on message m, where 
* sm = z|h|c
**************************************************/
PQMAGIC_EXPORT int crypto_sign_signature_internal(
  unsigned char *sig, 
  size_t *siglen, 
  const unsigned char *m, 
  size_t mlen, 
  const unsigned char *sk)
{
  size_t i, j;
  unsigned int n;
  unsigned char *buf; 
  uint16_t nonce = 0;
  poly     c, chat;
  polyvecl mat[PARAM_K], s1, y, yhat, z;
  polyveck s2, t0, w, w1;
  polyveck h, wcs2, wcs20, ct0, tmp;
  
  buf = (unsigned char *)malloc(2*SEEDBYTES + CRHBYTES + mlen);
  if(buf==NULL)
  	return -1;
  unpack_sk(buf,&s1, &s2, &t0, sk);

  for(i=0;i<mlen;i++)
  	buf[2*SEEDBYTES + CRHBYTES + i] = m[i];

#ifdef USE_SHAKE
  shake256(buf + 2*SEEDBYTES, CRHBYTES, buf + 2*SEEDBYTES, CRHBYTES + mlen);
#else
  sm3_extended(buf + 2*SEEDBYTES, CRHBYTES, buf + 2*SEEDBYTES, CRHBYTES + mlen);
#endif

  expand_mat(mat, buf);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

  rej:
  for(i = 0; i < PARAM_L; ++i)
    poly_uniform_gamma1m1(y.vec+i, &buf[SEEDBYTES], nonce++);

  yhat = y;
  polyvecl_ntt(&yhat);
  for(i = 0; i < PARAM_K; ++i) {
    polyvecl_pointwise_acc_invmontgomery(w.vec+i, mat+i, &yhat);//output coefficient  <=2*Q
    poly_invntt_montgomery(w.vec+i);//output coefficient  <= 2*Q
  }

  polyveck_freeze2q(&w);
  polyveck_decompose(&w1, &tmp, &w);
  challenge(&c, &buf[2*SEEDBYTES], &w1);

  chat = c;
  poly_ntt(&chat);
  for(i = 0; i < PARAM_L; ++i) {
    poly_pointwise_invmontgomery(z.vec+i, &chat, s1.vec+i);//output coefficient  <=2*Q
    poly_invntt_montgomery(z.vec+i);//output coefficient  <=2*Q
  }
  polyvecl_add(&z, &z, &y);//output coefficient  <=4*Q
  polyvecl_freeze4q(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA1))
    goto rej;

  for(i = 0; i < PARAM_K; ++i) {
    poly_pointwise_invmontgomery(wcs2.vec+i, &chat, s2.vec+i);//output coefficient  <=2*Q
    poly_invntt_montgomery(wcs2.vec+i);//output coefficient  <=2*Q
  }
  polyveck_sub(&wcs2, &w, &wcs2);//output coefficient  <=4*Q
  polyveck_freeze4q(&wcs2);
  polyveck_decompose(&tmp, &wcs20, &wcs2);//output coefficient  <=2*Q
  polyveck_freeze2q(&wcs20);
  if(polyveck_chknorm(&wcs20, GAMMA2 - BETA2))
    goto rej;

  for(i = 0; i < PARAM_K; ++i)
    for(j = 0; j < PARAM_N; ++j)
      if(tmp.vec[i].coeffs[j] != w1.vec[i].coeffs[j])
        goto rej;

  for(i = 0; i < PARAM_K; ++i) {
    poly_pointwise_invmontgomery(ct0.vec+i, &chat, t0.vec+i);//output coefficient  <=2*Q
    poly_invntt_montgomery(ct0.vec+i);//output coefficient  <=2*Q
  }
  polyveck_freeze2q(&ct0);
  if(polyveck_chknorm(&ct0, GAMMA2))
    goto rej;

  polyveck_add(&tmp, &wcs2, &ct0);//output coefficient  <=2*Q
  polyveck_neg(&ct0);
  polyveck_freeze2q(&tmp);
  n = polyveck_make_hint(&h, &tmp, &ct0);
  if(n > OMEGA)
    goto rej;

  pack_sig(sig, &z, &h, &c);

  *siglen = CRYPTO_BYTES;
  
  free(buf);
  return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - unsigned char *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - unsigned char *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - unsigned char *ctx:   pointer to ctx string
*              - size_t ctx_len: length of ctx string
*              - unsigned char *sk:    pointer to bit-packed secret key
*
* Returns 0 (success), -1 (context string too long error)
**************************************************/
PQMAGIC_EXPORT int crypto_sign_signature(unsigned char *sig,
                          size_t *siglen,
                          const unsigned char *m,
                          size_t mlen,
                          const unsigned char *ctx,
                          size_t ctx_len,
                          const unsigned char *sk)
{

  if(ctx_len > 255) {
    return -1;
  }

//   unsigned char coins[RNDBYTES];
  unsigned char *m_extended = (unsigned char*)malloc(mlen + ctx_len + 2);
  
// #ifdef AIGIS_SIG_RANDOMIZED_SIGNING
//   randombytes(coins, RNDBYTES);
// #else
//   memset(coins, 0, RNDBYTES);
// #endif

  m_extended[0] = 0;
  m_extended[1] = (unsigned char)ctx_len;
  if (ctx) {
  	memcpy(m_extended + 2, ctx, ctx_len);
  }
  memcpy(m_extended + 2 + ctx_len, m, mlen);

  int ret = crypto_sign_signature_internal(sig, siglen, m_extended, mlen + ctx_len + 2, sk);
  free(m_extended);
  return ret;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - unsigned char *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - unsigned char *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - unsigned char *ctx:   pointer to ctx string
*              - size_t ctx_len: length of ctx string
*              - unsigned char *sk: pointer to bit-packed secret key
*
* Returns 0 (success), -1 (context string too long error)
**************************************************/
PQMAGIC_EXPORT int crypto_sign(unsigned char *sm,
                size_t *smlen,
                const unsigned char *m,
                size_t mlen,
                const unsigned char *ctx,
                size_t ctx_len,
                const unsigned char *sk)
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
* Arguments:   - unsigned char *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const unsigned char *m: pointer to message
*              - size_t mlen: length of message
*              - const unsigned char *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
PQMAGIC_EXPORT int crypto_sign_verify_internal(
  const unsigned char *sig, size_t siglen,
  const unsigned char *m, size_t mlen,
  const unsigned char *pk)
{
  size_t i;
  unsigned char rho[SEEDBYTES];
  unsigned char *buf; 
  poly     c, chat, cp;
  polyvecl mat[PARAM_K], z;
  polyveck t1, w1, h, tmp1, tmp2;

  if(siglen < CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(&z, &h, &c, sig)) {
    return -1;
  }
  if(polyvecl_chknorm(&z, GAMMA1 - BETA1))
    return -1;
  
  buf = (unsigned char*)malloc(CRHBYTES + mlen);
  if(buf==NULL)
  	return -1;
  for(i=0;i<mlen;i++)
  	buf[CRHBYTES + i] = m[i];

#ifdef USE_SHAKE
  shake256(buf, CRHBYTES, pk, AIGIS_SIG_PUBLICKEYBYTES);
	shake256(buf, CRHBYTES, buf, CRHBYTES + mlen);
#else
  sm3_extended(buf, CRHBYTES, pk, AIGIS_SIG_PUBLICKEYBYTES);
	sm3_extended(buf, CRHBYTES, buf, CRHBYTES + mlen);
#endif

  expand_mat(mat, rho);
  
  polyvecl_ntt(&z);
  for(i = 0; i < PARAM_K ; ++i)
      polyvecl_pointwise_acc_invmontgomery(tmp1.vec+i, mat+i, &z);//output coefficient  <=2*Q

  chat = c;
  poly_ntt(&chat);
  polyveck_shiftl(&t1, PARAM_D);
  polyveck_ntt(&t1);
  for(i = 0; i < PARAM_K; ++i)
    poly_pointwise_invmontgomery(tmp2.vec+i, &chat, t1.vec+i);//output coefficient  <=2*Q

  polyveck_sub(&tmp1, &tmp1, &tmp2);//output coefficient  <=4*Q
  polyveck_invntt_montgomery(&tmp1);//output coefficient  <= 2*Q

  polyveck_freeze2q(&tmp1);
  polyveck_use_hint(&w1, &tmp1, &h);

  challenge(&cp, buf, &w1);
  for(i = 0; i < PARAM_N; ++i) {
    if(c.coeffs[i] != cp.coeffs[i]) {
      free(buf);
      return -1;
    }
  }

  free(buf);
  return 0;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - unsigned char *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const unsigned char *m: pointer to message
*              - size_t mlen: length of message
*              - unsigned char *ctx:   pointer to ctx string
*              - size_t ctx_len: length of ctx string
*              - const unsigned char *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
PQMAGIC_EXPORT int crypto_sign_verify(const unsigned char *sig,
                       size_t siglen,
                       const unsigned char *m,
                       size_t mlen,
                       const unsigned char *ctx,
                       size_t ctx_len,
                       const unsigned char *pk)
{

  if(ctx_len > 255) {
    return -1;
  }

  unsigned char *m_extended = (unsigned char*)malloc(mlen + ctx_len + 2);

  m_extended[0] = 0;
  m_extended[1] = (unsigned char)ctx_len;
  if (ctx) {
  	memcpy(m_extended + 2, ctx, ctx_len);
  }
  memcpy(m_extended + 2 + ctx_len, m, mlen);

  int ret = crypto_sign_verify_internal(sig, siglen, m_extended, mlen + ctx_len + 2, pk);
  free(m_extended);
  return ret;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - unsigned char *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const unsigned char *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - unsigned char *ctx:   pointer to ctx string
*              - size_t ctx_len: length of ctx string
*              - const unsigned char *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
PQMAGIC_EXPORT int crypto_sign_open(unsigned char *m,
                     size_t *mlen,
                     const unsigned char *sm,
                     size_t smlen,
                     const unsigned char *ctx,
                     size_t ctx_len,
                     const unsigned char *pk)
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

