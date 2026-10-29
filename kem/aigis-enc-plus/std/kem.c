#include <string.h>

#include "api.h"
#include "params.h"
#include "verify.h"
#include "owcpa.h"
#include "randombytes.h"
#include "hashkdf.h"


int mkem_keygen(uint8_t *pk, uint8_t *sk)
{
  size_t i;
  owcpa_keypair(pk, sk);
  for(i=0;i<PK_BYTES;i++)
    sk[POLYVEC_BYTES + i] = pk[i];
  Hash(sk+SK_BYTES-2*SEED_BYTES,pk,PK_BYTES); 
  randombytes(sk + SK_BYTES - SEED_BYTES, SEED_BYTES);/* Value z for implicit reject */
  
  return 0;
}

int mkem_enc(uint8_t *pk, uint8_t *ss, uint8_t *ct)
{
	uint8_t  kr[2*SEED_BYTES];                                        /* Will contain key, coins */
	uint8_t buf[3*SEED_BYTES];

	randombytes(buf, SEED_BYTES);

	Hash(buf + SEED_BYTES, pk, PK_BYTES);                               /* Multitarget countermeasure for coins + contributory KEM */

	Hash2(kr, buf, 2*SEED_BYTES);

	owcpa_enc(ct, buf, pk, kr + SEED_BYTES);                                         /* encrypt the pre-k using kr */
	memcpy(ss, kr, SEED_BYTES);                                       /* hash concatenation of pre-k and H(c) to k */
  return 0;
}


int mdkem_enc(uint8_t *pk, uint8_t *rnd,uint8_t *ss, uint8_t *ct)
{
	uint8_t  kr[SEED_BYTES];                                        /* Will contain key, coins */
	uint8_t buf[3 * SEED_BYTES];

	memcpy(buf, rnd, SEED_BYTES);
	Hash(buf + SEED_BYTES, pk, PK_BYTES);                               /* Multitarget countermeasure for coins + contributory KEM */

	Hash2(kr, buf, 2*SEED_BYTES);

	owcpa_enc(ct, buf, pk, kr + SEED_BYTES);                                         /* encrypt the pre-k using kr */
	memcpy(ss, kr, SEED_BYTES);                                     /* hash concatenation of pre-k and H(c) to k */
	return 0;
}

int mkem_dec(uint8_t *sk, uint8_t *ct, uint8_t *ss)
{
	size_t i;
	int fail;
	uint8_t cmp[CT_BYTES + 10];//to handle avx_compress_function
	uint8_t buf[3*SEED_BYTES];
	uint8_t buf2[SEED_BYTES + CT_BYTES];
	uint8_t kr[2*SEED_BYTES];                                         /* Will contain key, coins, qrom-hash */
	const uint8_t *pk = sk + POLYVEC_BYTES;

	owcpa_dec(buf, ct, sk);                                               /*obtaining pre-k*/

	for(i=0;i<SEED_BYTES;i++)                                             /* Multitarget countermeasure for coins + contributory KEM */
		buf[SEED_BYTES+i] = sk[SK_BYTES-2*SEED_BYTES+i];                    /* Save hash by storing H(pk) in sk */

	Hash2(kr, buf, 2*SEED_BYTES);
	memcpy(ss,kr,SEED_BYTES);
	owcpa_enc(cmp, buf, pk, kr+SEED_BYTES);                                          /* coins are in kr+SEED_BYTES */

	fail = verify(ct, cmp, CT_BYTES);

	memcpy(buf2, sk-SEED_BYTES, SEED_BYTES );
	memcpy(buf2 + SEED_BYTES, ct, CT_BYTES);
	KDF(buf2, SEED_BYTES, buf2, SEED_BYTES + CT_BYTES);                                 /* overwrite coins in kr with H(c)  */

	cmov(buf, buf2, SEED_BYTES, fail);                  /* Overwrite pre-k with z on re-encryption failure */
	fail = 0;
  return 0;
}