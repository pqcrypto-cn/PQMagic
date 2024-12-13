#include <stdio.h>
#include <string.h>
#include "api.h"
#include "genmatrix.h"
#include "hashkdf.h"
#include "ntt.h"
#include "owcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "utils/randombytes.h"


static void pack_pk(uint8_t *r, const polyvec *pk, const uint8_t *seed)
{
  int i;
  polyvec_pk_compress(r, pk);
  for(i=0;i<SEED_BYTES;i++)
    r[PK_POLYVEC_COMPRESSED_BYTES + i] = seed[i];
}
static void unpack_pk(polyvec *pk, uint8_t *seed, const uint8_t *packedpk)
{
	int i;
	for (i = 0; i < SEED_BYTES; i++)
		seed[i] = packedpk[PK_POLYVEC_COMPRESSED_BYTES + i];
	polyvec_pk_decompress(pk, packedpk);
}
static void pack_ciphertext(uint8_t *r, const polyvec *b, const poly *v)
{
	polyvec_ct_compress(r,b);
	poly_compress(r + CT_POLYVEC_COMPRESSED_BYTES, v);
}

static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t *c)
{
	polyvec_ct_decompress(b, c);
	poly_decompress(v, c + CT_POLYVEC_COMPRESSED_BYTES);
}

static void pack_sk(uint8_t *r, const polyvec *sk)
{
	polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk, const uint8_t *packedsk)
{
  polyvec_frombytes(sk, packedsk);
}

#define gen_a(A,B)  genmatrix(A,B,0)
#define gen_at(A,B) genmatrix(A,B,1)

void owcpa_keypair(
  uint8_t *pk, 
  uint8_t *sk,
  const uint8_t *coins)
{
  polyvec a[PARAM_K], e, pkpv, skpv;
  uint8_t buf[SEED_BYTES+SEED_BYTES];
  uint8_t *publicseed = buf;
  uint8_t *noiseseed = buf + SEED_BYTES;
  int i;
  uint8_t nonce=0;
  
  memcpy(buf, coins, SEED_BYTES);

  Hash2(buf,buf, SEED_BYTES);
  gen_a(a, publicseed);
 
  polyvec_ss_getnoise(&skpv,noiseseed,nonce);
  nonce += PARAM_K;

  polyvec_ntt(&skpv);

  polyvec_ee_getnoise(&e,noiseseed,nonce);
  nonce += PARAM_K;


  // matrix-vector multiplication
  for(i=0;i<PARAM_K;i++)
    polyvec_pointwise_acc(&pkpv.vec[i],&skpv,a+i);

  polyvec_invntt(&pkpv);
  polyvec_add(&pkpv,&pkpv,&e);

  //reduce to [0,PARAM_Q)
  polyvec_caddq(&pkpv);
  polyvec_caddq(&skpv);
  //pack sk and pk
  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed); 
}

void owcpa_enc(uint8_t *c,
               const uint8_t *m,
               const uint8_t *pk,
               const uint8_t *coins)
{
  polyvec sp, pkpv, ep, at[PARAM_K], bp;
  poly v, k, epp;
  uint8_t seed[SEED_BYTES];
  int i;
  uint8_t nonce=0;


  unpack_pk(&pkpv, seed, pk);

  poly_frommsg(&k, m); // 0 <= output < (Q+1)/2

  polyvec_ntt(&pkpv);
 
  gen_at(at, seed);

  polyvec_ss_getnoise(&sp,coins,nonce);
  nonce += PARAM_K;
  polyvec_ee_getnoise(&ep, coins, nonce);
  nonce += PARAM_K;
  poly_ee_getnoise(&epp, coins, nonce);


  polyvec_ntt(&sp);
  // matrix-vector multiplication
  for(i=0;i<PARAM_K;i++)
    polyvec_pointwise_acc(&bp.vec[i],&sp,at+i);

  polyvec_invntt(&bp);
  polyvec_add(&bp, &bp, &ep);

  polyvec_pointwise_acc(&v, &pkpv, &sp);
  poly_invntt(&v);

  poly_add(&v, &v, &epp);// less than Q in absolute value
  poly_sub(&v, &v, &k);// -2*Q < output <  (Q+1)/2

  //reduce to [0,PARAM_Q)
  poly_caddq2(&v);
  polyvec_caddq(&bp);
  //pack ct
  pack_ciphertext(c, &bp, &v);
}

void owcpa_dec(uint8_t *m,const uint8_t *c,const uint8_t *sk)
{
  polyvec bp, skpv;
  poly v, mp;

  unpack_ciphertext(&bp, &v, c);
  unpack_sk(&skpv, sk);

  polyvec_ntt(&bp);

  polyvec_pointwise_acc(&mp,&skpv,&bp);
  poly_invntt(&mp);
  poly_sub(&mp, &mp, &v);
  //reduce to [0,PARAM_Q)
  poly_caddq2(&mp);
  poly_tomsg(m, &mp);
}
