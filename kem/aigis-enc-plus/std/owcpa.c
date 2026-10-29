#include <string.h>
#include "api.h"
#include "owcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "ntt.h"
#include "gen_a.h"
#include "pack.h"
#include <stdio.h>



void owcpa_keypair(uint8_t *pk, 
                   uint8_t *sk)
{
  poly a;
  poly e, pkpv, skpv;
  uint8_t buf[SEED_BYTES+SEED_BYTES];
  uint8_t *noiseseed = buf;
  uint8_t *publicseed = buf + SEED_BYTES;

  randombytes(buf, SEED_BYTES);

  Hash2(buf,buf, SEED_BYTES);

  gen_a(&a, publicseed);
  poly_ss_getnoise(&skpv,noiseseed,0);
  poly_ntt(&skpv);
  poly_ee_getnoise(&e,noiseseed,1);

  poly_mont_mul(&pkpv, &skpv, &a);
  poly_getmontgomery(&pkpv);

  poly_invntt(&pkpv);
  poly_add(&pkpv,&pkpv,&e);

  poly_caddq(&pkpv);
  poly_caddq(&skpv);
  //pack sk and pk
  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed); 
}

void owcpa_enc(uint8_t *c,
               const uint8_t *m,
               const uint8_t *pk,
               const uint8_t *coins)
{
  poly r, pkpv, e1, a, u;
  poly v, k, e2;
  uint8_t seed[SEED_BYTES];

  unpack_pk(&pkpv, seed, pk);

  poly_frommsg(&k, m); // 0 <= output < (Q+1)/2

  poly_ntt(&pkpv);
 
  gen_a(&a, seed);

  poly_ss_getnoise(&r,coins,0);
  poly_ee_getnoise(&e1, coins, 1);
  poly_ee_getnoise(&e2, coins, 2);

  poly_ntt(&r);

  poly_mont_mul(&u, &r, &a);
  poly_getmontgomery(&u);

  poly_invntt(&u);
  poly_add(&u, &u, &e1);

  poly_mont_mul(&v, &pkpv, &r);
  poly_getmontgomery(&v);

  poly_invntt(&v);

  poly_add(&v, &v, &e2);// less than Q in absolute value
  poly_sub(&v, &v, &k);// -2*Q < output <  (Q+1)/2

  //reduce to [0,PARAM_Q)
  poly_caddq2(&v);
  poly_caddq(&u);
  //pack ct

  pack_ciphertext(c, &u, &v);

}

void owcpa_dec(uint8_t *m,const uint8_t *c,const uint8_t *sk)
{
  poly bp, skpv;
  poly v, mp;

  unpack_ciphertext(&bp, &v, c);
  unpack_sk(&skpv, sk);

  poly_ntt(&bp);

  poly_mont_mul(&mp,&skpv,&bp);
  poly_getmontgomery(&mp);

  poly_invntt(&mp);
  poly_sub(&mp, &mp, &v);
  //reduce to [0,PARAM_Q)
  poly_caddq2(&mp);
  poly_tomsg(m, &mp);

}
